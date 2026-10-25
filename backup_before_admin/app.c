#include "setting.h"
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "esp_log.h"
#include "esp_err.h"
#include "esp_random.h"
#include "esp_http_server.h"
#include "driver/gpio.h"

#include "nvs.h"
#include "nvs_flash.h"

#include "psa/crypto.h"
#include "cJSON.h"

#include "app.h"
#include "wifi_manager.h"

/* ---------------- Configuration ---------------- */

#define TAG                 "DOOR_APP"
#define DOOR_GPIO           GPIO_NUM_2

/* Change this value to set the registration limit. */
#define MAX_DEVICES         1
#define DEVICE_NAME_LEN     24

#define TOKEN_HEX_LEN       32
#define TOKEN_HASH_LEN      32

#define NVS_NAMESPACE       "door_auth"
#define NVS_KEY             "auth_db"
#define AUTH_DB_MAGIC       0x44524C31

/* Demo PIN: change this before testing. */
#define ADMIN_PIN           "842617"

/* ---------------- Device database ---------------- */

typedef struct {
    char name[DEVICE_NAME_LEN];
    uint8_t token_hash[TOKEN_HASH_LEN];
} device_record_t;

typedef struct {
    uint32_t magic;
    uint32_t count;
    device_record_t devices[MAX_DEVICES];
} auth_db_t;

static auth_db_t s_auth_db;
static httpd_handle_t s_http_server = NULL;
static bool s_psa_initialized = false;

/* ---------------- SHA-256 using PSA Crypto ---------------- */

static bool sha256_hash(const uint8_t *data,
                        size_t data_len,
                        uint8_t hash[TOKEN_HASH_LEN])
{
    if (!s_psa_initialized) {
        psa_status_t status = psa_crypto_init();

        if (status != PSA_SUCCESS) {
            ESP_LOGE(TAG, "PSA initialization failed: %ld",
                     (long)status);
            return false;
        }

        s_psa_initialized = true;
    }

    size_t hash_len = 0;

    psa_status_t status = psa_hash_compute(
        PSA_ALG_SHA_256,
        data,
        data_len,
        hash,
        TOKEN_HASH_LEN,
        &hash_len
    );

    if (status != PSA_SUCCESS || hash_len != TOKEN_HASH_LEN) {
        ESP_LOGE(TAG, "SHA-256 failed: %ld", (long)status);
        return false;
    }

    return true;
}

/* ---------------- NVS persistence ---------------- */

static esp_err_t auth_db_save(void)
{
    nvs_handle_t handle;

    esp_err_t err = nvs_open(
        NVS_NAMESPACE, NVS_READWRITE, &handle
    );

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "NVS open failed: %s", esp_err_to_name(err));
        return err;
    }

    err = nvs_set_blob(handle, NVS_KEY,
                       &s_auth_db, sizeof(s_auth_db));

    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }

    nvs_close(handle);

    if (err == ESP_OK) {
        ESP_LOGI(TAG, "Saved %lu registered devices",
                 (unsigned long)s_auth_db.count);
    } else {
        ESP_LOGE(TAG, "NVS save failed: %s", esp_err_to_name(err));
    }

    return err;
}

static esp_err_t auth_db_load(void)
{
    nvs_handle_t handle;

    esp_err_t err = nvs_open(
        NVS_NAMESPACE, NVS_READWRITE, &handle
    );

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "NVS open failed: %s", esp_err_to_name(err));
        return err;
    }

    size_t blob_size = sizeof(s_auth_db);

    err = nvs_get_blob(
        handle, NVS_KEY, &s_auth_db, &blob_size
    );

    nvs_close(handle);

    if (err == ESP_ERR_NVS_NOT_FOUND ||
        err == ESP_ERR_NVS_INVALID_LENGTH ||
        (err == ESP_OK && blob_size != sizeof(s_auth_db))) {

        ESP_LOGW(TAG, "No compatible database; initializing");

        memset(&s_auth_db, 0, sizeof(s_auth_db));
        s_auth_db.magic = AUTH_DB_MAGIC;

        return auth_db_save();
    }

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "NVS load failed: %s", esp_err_to_name(err));
        return err;
    }

    if (s_auth_db.magic != AUTH_DB_MAGIC ||
        s_auth_db.count > MAX_DEVICES) {

        ESP_LOGW(TAG, "Invalid database; initializing");

        memset(&s_auth_db, 0, sizeof(s_auth_db));
        s_auth_db.magic = AUTH_DB_MAGIC;

        return auth_db_save();
    }

    ESP_LOGI(TAG, "Loaded %lu registered devices",
             (unsigned long)s_auth_db.count);

    return ESP_OK;
}

/* ---------------- Token utilities ---------------- */

static void generate_token(char token[TOKEN_HEX_LEN + 1])
{
    static const char hex[] = "0123456789abcdef";

    for (size_t i = 0; i < TOKEN_HEX_LEN / 2; i++) {
        uint8_t b = (uint8_t)(esp_random() & 0xFF);
        token[i * 2] = hex[b >> 4];
        token[i * 2 + 1] = hex[b & 0x0F];
    }

    token[TOKEN_HEX_LEN] = '\0';
}

static bool token_matches(const char *token)
{
    if (token == NULL || strlen(token) != TOKEN_HEX_LEN) {
        return false;
    }

    uint8_t candidate_hash[TOKEN_HASH_LEN];

    if (!sha256_hash((const uint8_t *)token,
                     strlen(token), candidate_hash)) {
        return false;
    }

    for (uint32_t i = 0; i < s_auth_db.count; i++) {
        uint8_t difference = 0;

        for (size_t j = 0; j < TOKEN_HASH_LEN; j++) {
            difference |= candidate_hash[j] ^
                          s_auth_db.devices[i].token_hash[j];
        }

        if (difference == 0) {
            return true;
        }
    }

    return false;
}

/* ---------------- HTTP helpers ---------------- */

static esp_err_t send_error(httpd_req_t *req,
                            const char *status,
                            const char *message)
{
    httpd_resp_set_status(req, status);
    httpd_resp_set_type(req, "text/plain");
    return httpd_resp_sendstr(req, message);
}

/* ---------------- Web page ---------------- */

static const char INDEX_HTML[] =
"<!DOCTYPE html><html><head>"
"<meta name='viewport' content='width=device-width, initial-scale=1'>"
"<title>ESP32 Door Lock</title>"
"<style>"
"body{font-family:Arial,sans-serif;max-width:440px;margin:35px auto;"
"padding:18px;background:#f4f6f8;color:#222}"
".card{background:white;padding:20px;margin:15px 0;border-radius:12px;"
"box-shadow:0 2px 8px #0001}"
"input,button{box-sizing:border-box;width:100%;padding:12px;margin:7px 0;"
"font-size:16px}"
"button{border:0;border-radius:7px;color:white;background:#2457a7}"
".unlock{background:#b42318}.lock{background:#167647}"
"#status{overflow-wrap:anywhere}"
"</style></head><body>"

"<h2>ESP32 Wi-Fi Door Lock</h2>"

"<div class='card' id='registrationCard'>"
"<h3>Register this phone</h3>"
"<p id='registrationInfo'>Checking registration availability...</p>"
"<input id='name' maxlength='23' placeholder='Phone/device name'>"
"<input id='pin' type='password' placeholder='Administrator PIN'>"
"<button id='registerButton' onclick='registerDevice()'>"
"Register device</button>"
"</div>"

"<div class='card'>"
"<h3>Door output demo</h3>"
"<p id='device'>Checking saved registration...</p>"
"<button class='unlock' onclick='setOutput(1)'>Unlock output</button>"
"<button class='lock' onclick='setOutput(0)'>Lock output</button>"
"<button onclick='forgetToken()'>Forget registration on this phone</button>"
"<p id='status'></p>"
"</div>"

"<script>"
"const statusEl=document.getElementById('status');"
"function show(s){statusEl.textContent=s;}"

"function updateDevice(){"
"const name=localStorage.getItem('door_device_name');"
"document.getElementById('device').textContent=name?"
"('Registered on this phone: '+name):"
"'This browser has no saved registration token.';"
"}"

"async function updateRegistrationStatus(){"
"const card=document.getElementById('registrationCard');"
"const info=document.getElementById('registrationInfo');"
"const button=document.getElementById('registerButton');"
"try{"
"const r=await fetch('/registration-status');"
"if(!r.ok)throw new Error('status request failed');"
"const s=await r.json();"
"if(s.registration_open){"
"card.style.display='block';"
"info.textContent='Registered devices: '+s.registered+' / '+s.max_devices;"
"button.disabled=false;"
"}else{"
"card.style.display='none';"
"}"
"}catch(e){"
"card.style.display='block';"
"info.textContent='Could not check registration availability.';"
"button.disabled=true;"
"}"
"}"

"async function registerDevice(){"
"const name=document.getElementById('name').value.trim();"
"const pin=document.getElementById('pin').value;"
"if(!name||!pin){show('Enter a device name and administrator PIN.');return;}"
"const button=document.getElementById('registerButton');"
"button.disabled=true;"
"try{"
"const r=await fetch('/register-device',{method:'POST',"
"headers:{'Content-Type':'application/json'},"
"body:JSON.stringify({name:name,admin_pin:pin})});"
"const d=await r.json();"
"if(!r.ok){show(d.error||'Registration failed.');return;}"
"localStorage.setItem('door_device_token',d.token);"
"localStorage.setItem('door_device_name',d.name);"
"document.getElementById('pin').value='';"
"show('Device registered successfully.');"
"updateDevice();"
"await updateRegistrationStatus();"
"}catch(e){show('Registration request failed.');}"
"finally{button.disabled=false;}"
"}"

"async function setOutput(state){"
"const token=localStorage.getItem('door_device_token');"
"if(!token){show('This phone is not registered.');return;}"
"try{"
"const r=await fetch('/gpio?state='+state,"
"{headers:{'X-Device-Token':token}});"
"const t=await r.text();"
"show(r.ok?t:('Request rejected: '+t));"
"}catch(e){show('Could not contact ESP32.');}"
"}"

"function forgetToken(){"
"localStorage.removeItem('door_device_token');"
"localStorage.removeItem('door_device_name');"
"updateDevice();"
"show('Token removed from this browser only. The ESP32 registration remains.');"
"}"

"updateDevice();"
"updateRegistrationStatus();"
"</script></body></html>";

static esp_err_t root_get_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(req, INDEX_HTML, HTTPD_RESP_USE_STRLEN);
}

/* ---------------- Registration status endpoint ---------------- */

static esp_err_t registration_status_handler(httpd_req_t *req)
{
    cJSON *response = cJSON_CreateObject();

    if (response == NULL) {
        return send_error(req, "500 Internal Server Error",
                          "Could not create response");
    }

    cJSON_AddNumberToObject(response, "registered",
                            s_auth_db.count);
    cJSON_AddNumberToObject(response, "max_devices",
                            MAX_DEVICES);
    cJSON_AddBoolToObject(response, "registration_open",
                          s_auth_db.count < MAX_DEVICES);

    char *text = cJSON_PrintUnformatted(response);
    cJSON_Delete(response);

    if (text == NULL) {
        return send_error(req, "500 Internal Server Error",
                          "Could not create response");
    }

    httpd_resp_set_type(req, "application/json");
    esp_err_t err = httpd_resp_send(req, text, HTTPD_RESP_USE_STRLEN);
    cJSON_free(text);

    return err;
}

/* ---------------- Device registration endpoint ---------------- */

static esp_err_t register_device_handler(httpd_req_t *req)
{
    if (req->content_len <= 0 || req->content_len > 512) {
        return send_error(req, "400 Bad Request",
                          "Invalid request size");
    }

    char body[513];
    size_t received = 0;

    while (received < (size_t)req->content_len) {
        int ret = httpd_req_recv(
            req, body + received,
            (size_t)req->content_len - received
        );

        if (ret <= 0) {
            return send_error(req, "400 Bad Request",
                              "Could not read request");
        }

        received += (size_t)ret;
    }

    body[received] = '\0';

    cJSON *json = cJSON_Parse(body);

    if (json == NULL) {
        return send_error(req, "400 Bad Request", "Invalid JSON");
    }

    const cJSON *name_item =
        cJSON_GetObjectItemCaseSensitive(json, "name");
    const cJSON *pin_item =
        cJSON_GetObjectItemCaseSensitive(json, "admin_pin");

    if (!cJSON_IsString(name_item) ||
        !cJSON_IsString(pin_item) ||
        name_item->valuestring == NULL ||
        pin_item->valuestring == NULL) {
        cJSON_Delete(json);
        return send_error(req, "400 Bad Request",
                          "Device name and PIN are required");
    }

    size_t name_len = strlen(name_item->valuestring);

    if (name_len == 0 || name_len >= DEVICE_NAME_LEN) {
        cJSON_Delete(json);
        return send_error(req, "400 Bad Request",
                          "Device name must be 1 to 23 characters");
    }

    if (strcmp(pin_item->valuestring, ADMIN_PIN) != 0) {
        cJSON_Delete(json);
        ESP_LOGW(TAG, "Registration rejected: invalid PIN");
        return send_error(req, "401 Unauthorized",
                          "Invalid administrator PIN");
    }

    char device_name[DEVICE_NAME_LEN];
    memcpy(device_name, name_item->valuestring, name_len + 1);
    cJSON_Delete(json);

    /* Server-side limit: cannot be bypassed by hiding the form. */
    if (s_auth_db.count >= MAX_DEVICES) {
        return send_error(req, "409 Conflict",
                          "Device registration limit reached");
    }

    char token[TOKEN_HEX_LEN + 1];
    uint8_t hash[TOKEN_HASH_LEN];

    generate_token(token);

    if (!sha256_hash((const uint8_t *)token, TOKEN_HEX_LEN, hash)) {
        return send_error(req, "500 Internal Server Error",
                          "Could not create device credential");
    }

    uint32_t index = s_auth_db.count;

    memset(&s_auth_db.devices[index], 0,
           sizeof(s_auth_db.devices[index]));

    memcpy(s_auth_db.devices[index].name,
           device_name, strlen(device_name) + 1);
    memcpy(s_auth_db.devices[index].token_hash, hash, sizeof(hash));

    s_auth_db.count++;

    esp_err_t err = auth_db_save();

    if (err != ESP_OK) {
        s_auth_db.count--;
        memset(&s_auth_db.devices[index], 0,
               sizeof(s_auth_db.devices[index]));

        return send_error(req, "500 Internal Server Error",
                          "Could not save device registration");
    }

    ESP_LOGI(TAG, "Registered device: %s", device_name);

    cJSON *response = cJSON_CreateObject();

    if (response == NULL) {
        return send_error(req, "500 Internal Server Error",
                          "Registered but response creation failed");
    }

    cJSON_AddStringToObject(response, "name", device_name);
    cJSON_AddStringToObject(response, "token", token);

    char *response_text = cJSON_PrintUnformatted(response);
    cJSON_Delete(response);

    if (response_text == NULL) {
        return send_error(req, "500 Internal Server Error",
                          "Could not create registration response");
    }

    httpd_resp_set_type(req, "application/json");
    err = httpd_resp_send(req, response_text, HTTPD_RESP_USE_STRLEN);
    cJSON_free(response_text);

    return err;
}

/* ---------------- Authorized GPIO endpoint ---------------- */

static esp_err_t gpio_handler(httpd_req_t *req)
{
    char token[TOKEN_HEX_LEN + 1];

    if (httpd_req_get_hdr_value_str(
            req, "X-Device-Token", token, sizeof(token)) != ESP_OK) {
        ESP_LOGW(TAG, "GPIO request rejected: missing token");
        return send_error(req, "401 Unauthorized",
                          "Device credential required");
    }

    if (!token_matches(token)) {
        ESP_LOGW(TAG, "GPIO request rejected: invalid token");
        return send_error(req, "401 Unauthorized",
                          "Invalid device credential");
    }

    char query[32];
    char state_text[8];

    if (httpd_req_get_url_query_str(req, query, sizeof(query)) != ESP_OK ||
        httpd_query_key_value(query, "state",
                              state_text, sizeof(state_text)) != ESP_OK) {
        return send_error(req, "400 Bad Request",
                          "Missing state parameter");
    }

    int state;

    if (strcmp(state_text, "1") == 0) {
        state = 1;
    } else if (strcmp(state_text, "0") == 0) {
        state = 0;
    } else {
        return send_error(req, "400 Bad Request",
                          "State must be 0 or 1");
    }

    esp_err_t err = gpio_set_level(DOOR_GPIO, state);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "GPIO failed: %s", esp_err_to_name(err));
        return send_error(req, "500 Internal Server Error",
                          "GPIO operation failed");
    }

    ESP_LOGI(TAG, "Authorized GPIO request: GPIO%d = %d",
             (int)DOOR_GPIO, state);

    httpd_resp_set_type(req, "text/plain");

    return httpd_resp_sendstr(
        req,
        state ? "Unlock output activated (GPIO HIGH)"
              : "Lock output activated (GPIO LOW)"
    );
}

/* ---------------- Web server ---------------- */

static esp_err_t web_server_start(void)
{
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.max_uri_handlers = 8;

    esp_err_t err = httpd_start(&s_http_server, &config);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "HTTP server start failed: %s",
                 esp_err_to_name(err));
        return err;
    }

    httpd_uri_t root_uri = {
        .uri = "/",
        .method = HTTP_GET,
        .handler = root_get_handler,
        .user_ctx = NULL
    };

    httpd_uri_t register_page_uri = {
        .uri = "/register",
        .method = HTTP_GET,
        .handler = root_get_handler,
        .user_ctx = NULL
    };

    httpd_uri_t registration_status_uri = {
        .uri = "/registration-status",
        .method = HTTP_GET,
        .handler = registration_status_handler,
        .user_ctx = NULL
    };

    httpd_uri_t register_device_uri = {
        .uri = "/register-device",
        .method = HTTP_POST,
        .handler = register_device_handler,
        .user_ctx = NULL
    };

    httpd_uri_t gpio_uri = {
        .uri = "/gpio",
        .method = HTTP_GET,
        .handler = gpio_handler,
        .user_ctx = NULL
    };

    httpd_register_uri_handler(s_http_server, &root_uri);
    httpd_register_uri_handler(s_http_server, &register_page_uri);
    httpd_register_uri_handler(s_http_server, &registration_status_uri);
    httpd_register_uri_handler(s_http_server, &register_device_uri);
    httpd_register_uri_handler(s_http_server, &gpio_uri);

    ESP_LOGI(TAG, "Web server started");
    ESP_LOGI(TAG, "Open http://192.168.4.1/ on a connected device");

    return ESP_OK;
}

/* ---------------- Application entry point ---------------- */


esp_err_t app_start(void)
{
    ESP_LOGI(TAG, "Starting Wi-Fi door lock application");

    gpio_config_t gpio_config_data = {
        .pin_bit_mask = (1ULL << DOOR_GPIO),
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE
    };

    esp_err_t err = gpio_config(&gpio_config_data);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "GPIO configuration failed: %s",
                 esp_err_to_name(err));
        return err;
    }

    gpio_set_level(DOOR_GPIO, 0);

    /* Load the existing registered-phone database. */
    err = auth_db_load();
    if (err != ESP_OK) {
        return err;
    }

    /* Start the ESP32 Wi-Fi access point. */
    err = wifi_manager_start();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Wi-Fi manager failed: %s",
                 esp_err_to_name(err));
        return err;
    }

    /* Start the phone Lock/Unlock page on port 80. */
    err = web_server_start();
    if (err != ESP_OK) {
        return err;
    }

    /* Start the administrator page on port 8080. */
    err = setting_start();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Admin settings server failed: %s",
                 esp_err_to_name(err));
        return err;
    }

    ESP_LOGI(TAG, "Phone page: http://192.168.4.1/");
    ESP_LOGI(TAG, "Admin page: http://192.168.4.1:8080/");
    ESP_LOGI(TAG, "Application started successfully");

    return ESP_OK;
}

