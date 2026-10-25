#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#include "esp_http_server.h"
#include "esp_err.h"
#include "cJSON.h"

#include "setting.h"
#include "auth_api.h"

#define TAG "SETTING"
#define ADMIN_PORT 8080
#define ADMIN_BODY_MAX 512
#define TOKEN_HEX_LEN 32

static httpd_handle_t settings_server = NULL;

static const char ADMIN_PAGE[] =
"<!DOCTYPE html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'>"
"<title>Door Lock Admin</title><style>"
"body{font-family:Arial,sans-serif;max-width:520px;margin:28px auto;padding:16px;background:#f4f6f8;color:#222}"
".card{background:#fff;padding:18px;margin:14px 0;border-radius:12px;box-shadow:0 2px 8px #0001}"
"input,button{box-sizing:border-box;width:100%;padding:12px;margin:7px 0;font-size:16px}"
"button{border:0;border-radius:7px;background:#2457a7;color:white}"
".danger{background:#b42318}#result{overflow-wrap:anywhere}a{overflow-wrap:anywhere}"
"</style></head><body><h2>Door Lock Administrator</h2>"
"<div class='card'><h3>Registration status</h3><p id='count'>Loading...</p><button onclick='refreshStatus()'>Refresh status</button></div>"
"<div class='card'><h3>Register a phone</h3><p>Register one phone at a time. Keep the generated registration link private.</p>"
"<input id='deviceName' maxlength='23' placeholder='Phone/device name'>"
"<input id='pin' type='password' autocomplete='current-password' placeholder='Administrator PIN'>"
"<button id='registerBtn' onclick='registerDevice()'>Register phone</button><p id='result' role='status'></p></div>"
"<div class='card'><h3>Delete all registrations</h3><p>This revokes every registered phone credential. All phones will need to be registered again.</p>"
"<button class='danger' onclick='deleteAll()'>Delete all registrations</button></div>"
"<script>const pinEl=document.getElementById('pin');const resultEl=document.getElementById('result');"
"function say(s){resultEl.textContent=s;}"
"async function refreshStatus(){try{const r=await fetch('/registration-status');if(!r.ok)throw Error();const d=await r.json();"
"document.getElementById('count').textContent='Registered phones: '+d.registered+' / '+d.max_devices+(d.registration_open?' — registration available':' — limit reached');"
"}catch(e){document.getElementById('count').textContent='Could not read registration status.';}}"
"async function registerDevice(){const name=document.getElementById('deviceName').value.trim();const pin=pinEl.value;"
"if(!name||!pin){say('Enter a phone name and administrator PIN.');return;}"
"const b=document.getElementById('registerBtn');b.disabled=true;"
"try{const r=await fetch('/register-device',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:name,admin_pin:pin})});"
"const d=await r.json();if(!r.ok){say(d.error||'Registration failed.');return;}"
"const link='http://192.168.4.1/?token='+encodeURIComponent(d.token);"
"say('Registered '+d.name+'. Open this link on the phone that should control the lock: '+link);"
"const a=document.createElement('a');a.href=link;a.textContent='Open phone control page with this credential';a.target='_blank';a.rel='noopener';resultEl.appendChild(document.createElement('br'));resultEl.appendChild(a);"
"const copy=document.createElement('button');copy.textContent='Copy registration link';copy.onclick=async()=>{try{await navigator.clipboard.writeText(link);say('Registration link copied: '+link);resultEl.appendChild(document.createElement('br'));resultEl.appendChild(a);}catch(e){say('Copy unavailable. Copy this link manually: '+link);}};resultEl.appendChild(copy);"
"document.getElementById('deviceName').value='';pinEl.value='';await refreshStatus();"
"}catch(e){say('Registration request failed.');}finally{b.disabled=false;}}"
"async function deleteAll(){const pin=pinEl.value;if(!pin){say('Enter the administrator PIN first.');return;}"
"if(!confirm('Delete ALL registered phones? Previously issued credentials will stop working.'))return;"
"try{const r=await fetch('/delete-all',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({admin_pin:pin})});"
"const d=await r.json();if(!r.ok){say(d.error||'Delete-all failed.');return;}say('All phone registrations have been deleted.');pinEl.value='';await refreshStatus();"
"}catch(e){say('Delete-all request failed.');}}refreshStatus();</script></body></html>";

static esp_err_t send_text_error(httpd_req_t *req, const char *status,
                                 const char *message)
{
    httpd_resp_set_status(req, status);
    httpd_resp_set_type(req, "application/json");
    cJSON *obj = cJSON_CreateObject();
    if (obj == NULL) return httpd_resp_sendstr(req, "{\"error\":\"Internal error\"}");
    cJSON_AddStringToObject(obj, "error", message);
    char *body = cJSON_PrintUnformatted(obj);
    cJSON_Delete(obj);
    if (body == NULL) return httpd_resp_sendstr(req, "{\"error\":\"Internal error\"}");
    esp_err_t err = httpd_resp_send(req, body, HTTPD_RESP_USE_STRLEN);
    cJSON_free(body);
    return err;
}

static esp_err_t read_json_body(httpd_req_t *req, cJSON **json_out)
{
    if (req->content_len <= 0 || req->content_len > ADMIN_BODY_MAX) {
        send_text_error(req, "400 Bad Request", "Invalid request size");
        return ESP_ERR_INVALID_ARG;
    }
    char body[ADMIN_BODY_MAX + 1];
    size_t received = 0;
    while (received < (size_t)req->content_len) {
        int ret = httpd_req_recv(req, body + received,
                                 (size_t)req->content_len - received);
        if (ret <= 0) {
            send_text_error(req, "400 Bad Request", "Could not read request");
            return ESP_FAIL;
        }
        received += (size_t)ret;
    }
    body[received] = '\0';
    *json_out = cJSON_Parse(body);
    if (*json_out == NULL) {
        send_text_error(req, "400 Bad Request", "Invalid JSON");
        return ESP_ERR_INVALID_ARG;
    }
    return ESP_OK;
}

static const char *get_string(cJSON *json, const char *key)
{
    cJSON *item = cJSON_GetObjectItemCaseSensitive(json, key);
    return cJSON_IsString(item) ? item->valuestring : NULL;
}

static esp_err_t root_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    return httpd_resp_send(req, ADMIN_PAGE, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t registration_status_handler(httpd_req_t *req)
{
    uint32_t registered = 0, maximum = 0;
    esp_err_t err = auth_get_status(&registered, &maximum);
    if (err != ESP_OK) return send_text_error(req, "500 Internal Server Error", "Could not read status");
    cJSON *obj = cJSON_CreateObject();
    if (obj == NULL) return send_text_error(req, "500 Internal Server Error", "Out of memory");
    cJSON_AddNumberToObject(obj, "registered", registered);
    cJSON_AddNumberToObject(obj, "max_devices", maximum);
    cJSON_AddBoolToObject(obj, "registration_open", registered < maximum);
    char *body = cJSON_PrintUnformatted(obj);
    cJSON_Delete(obj);
    if (body == NULL) return send_text_error(req, "500 Internal Server Error", "Out of memory");
    httpd_resp_set_type(req, "application/json");
    err = httpd_resp_send(req, body, HTTPD_RESP_USE_STRLEN);
    cJSON_free(body);
    return err;
}

static esp_err_t register_device_handler(httpd_req_t *req)
{
    cJSON *json = NULL;
    esp_err_t err = read_json_body(req, &json);
    if (err != ESP_OK) return err;
    const char *name = get_string(json, "name");
    const char *pin = get_string(json, "admin_pin");
    if (name == NULL || pin == NULL || strlen(name) == 0 || strlen(name) > 23) {
        cJSON_Delete(json);
        return send_text_error(req, "400 Bad Request", "Phone name (1 to 23 characters) and PIN are required");
    }
    char name_copy[24];
    char pin_copy[64];
    if (strlen(pin) >= sizeof(pin_copy)) {
        cJSON_Delete(json);
        return send_text_error(req, "401 Unauthorized", "Invalid administrator PIN");
    }
    strcpy(name_copy, name);
    strcpy(pin_copy, pin);
    cJSON_Delete(json);

    char token[TOKEN_HEX_LEN + 1];
    err = auth_register_device(name_copy, pin_copy, token, sizeof(token));
    memset(pin_copy, 0, sizeof(pin_copy));
    if (err == ESP_ERR_INVALID_STATE) return send_text_error(req, "409 Conflict", "Device registration limit reached");
    if (err == ESP_ERR_INVALID_ARG) return send_text_error(req, "401 Unauthorized", "Invalid administrator PIN or phone name");
    if (err != ESP_OK) return send_text_error(req, "500 Internal Server Error", "Could not save phone registration");

    cJSON *response = cJSON_CreateObject();
    if (response == NULL) return send_text_error(req, "500 Internal Server Error", "Registered but response creation failed");
    cJSON_AddStringToObject(response, "name", name_copy);
    cJSON_AddStringToObject(response, "token", token);
    char *body = cJSON_PrintUnformatted(response);
    cJSON_Delete(response);
    if (body == NULL) return send_text_error(req, "500 Internal Server Error", "Could not create response");
    httpd_resp_set_type(req, "application/json");
    err = httpd_resp_send(req, body, HTTPD_RESP_USE_STRLEN);
    cJSON_free(body);
    memset(token, 0, sizeof(token));
    return err;
}

static esp_err_t delete_all_handler(httpd_req_t *req)
{
    cJSON *json = NULL;
    esp_err_t err = read_json_body(req, &json);
    if (err != ESP_OK) return err;
    const char *pin = get_string(json, "admin_pin");
    char pin_copy[64];
    if (pin == NULL || strlen(pin) >= sizeof(pin_copy)) {
        cJSON_Delete(json);
        return send_text_error(req, "400 Bad Request", "Administrator PIN is required");
    }
    strcpy(pin_copy, pin);
    cJSON_Delete(json);
    err = auth_delete_all(pin_copy);
    memset(pin_copy, 0, sizeof(pin_copy));
    if (err == ESP_ERR_INVALID_ARG) return send_text_error(req, "401 Unauthorized", "Invalid administrator PIN");
    if (err != ESP_OK) return send_text_error(req, "500 Internal Server Error", "Could not delete registrations");
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, "{\"ok\":true}");
}

esp_err_t setting_start(void)
{
    if (settings_server != NULL) return ESP_OK;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = ADMIN_PORT;
    config.ctrl_port = 32769;
    config.max_uri_handlers = 4;
    esp_err_t err = httpd_start(&settings_server, &config);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start settings server: %s", esp_err_to_name(err));
        return err;
    }
    httpd_uri_t root = {.uri="/", .method=HTTP_GET, .handler=root_handler, .user_ctx=NULL};
    httpd_uri_t status = {.uri="/registration-status", .method=HTTP_GET, .handler=registration_status_handler, .user_ctx=NULL};
    httpd_uri_t reg = {.uri="/register-device", .method=HTTP_POST, .handler=register_device_handler, .user_ctx=NULL};
    httpd_uri_t del = {.uri="/delete-all", .method=HTTP_POST, .handler=delete_all_handler, .user_ctx=NULL};
    if ((err = httpd_register_uri_handler(settings_server, &root)) != ESP_OK ||
        (err = httpd_register_uri_handler(settings_server, &status)) != ESP_OK ||
        (err = httpd_register_uri_handler(settings_server, &reg)) != ESP_OK ||
        (err = httpd_register_uri_handler(settings_server, &del)) != ESP_OK) {
        ESP_LOGE(TAG, "Could not register admin endpoints: %s", esp_err_to_name(err));
        httpd_stop(settings_server);
        settings_server = NULL;
        return err;
    }
    ESP_LOGI(TAG, "Admin settings page started on port %d", ADMIN_PORT);
    return ESP_OK;
}
