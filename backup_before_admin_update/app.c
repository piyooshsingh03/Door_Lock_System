#include "sos.h"
#include "setting.h"
#include "auth_api.h"
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

#include "app.h"
#include "wifi_manager.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

/* ---------------- Configuration ---------------- */

#define TAG                 "DOOR_APP"
#define DOOR_GPIO           GPIO_NUM_2

/* Change this value to set the registration limit. */
#define MAX_DEVICES         2
#define DEVICE_NAME_LEN     24

#define TOKEN_HEX_LEN       32
#define TOKEN_HASH_LEN      32

#define NVS_NAMESPACE       "door_auth"
#define NVS_KEY             "auth_db"
#define AUTH_DB_MAGIC       0x44524C31

/* Demo PIN: change this before testing. */
#define ADMIN_PIN           "185226"

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
static SemaphoreHandle_t s_auth_mutex = NULL;

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
    if (s_auth_mutex == NULL) {
        return false;
    }

    bool matched = false;
    xSemaphoreTake(s_auth_mutex, portMAX_DELAY);
    for (uint32_t i = 0; i < s_auth_db.count; i++) {
        uint8_t difference = 0;
        for (size_t j = 0; j < TOKEN_HASH_LEN; j++) {
            difference |= candidate_hash[j] ^ s_auth_db.devices[i].token_hash[j];
        }
        if (difference == 0) {
            matched = true;
            break;
        }
    }
    xSemaphoreGive(s_auth_mutex);
    return matched;
}

/* ---------------- Shared administrator/authentication API ---------------- */

esp_err_t auth_get_status(uint32_t *registered, uint32_t *maximum)
{
    if (registered == NULL || maximum == NULL || s_auth_mutex == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    xSemaphoreTake(s_auth_mutex, portMAX_DELAY);
    *registered = s_auth_db.count;
    *maximum = MAX_DEVICES;
    xSemaphoreGive(s_auth_mutex);
    return ESP_OK;
}

esp_err_t auth_register_device(const char *name, const char *pin,
                               char *token_out, size_t token_out_size)
{
    if (name == NULL || pin == NULL || token_out == NULL ||
        token_out_size < TOKEN_HEX_LEN + 1 || s_auth_mutex == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    size_t name_len = strlen(name);
    if (name_len == 0 || name_len >= DEVICE_NAME_LEN) {
        return ESP_ERR_INVALID_ARG;
    }
    if (strcmp(pin, ADMIN_PIN) != 0) {
        ESP_LOGW(TAG, "Registration rejected: invalid administrator PIN");
        return ESP_ERR_INVALID_ARG;
    }

    xSemaphoreTake(s_auth_mutex, portMAX_DELAY);
    if (s_auth_db.count >= MAX_DEVICES) {
        xSemaphoreGive(s_auth_mutex);
        return ESP_ERR_INVALID_STATE;
    }

    char token[TOKEN_HEX_LEN + 1];
    uint8_t hash[TOKEN_HASH_LEN];
    generate_token(token);
    if (!sha256_hash((const uint8_t *)token, TOKEN_HEX_LEN, hash)) {
        xSemaphoreGive(s_auth_mutex);
        return ESP_FAIL;
    }

    uint32_t index = s_auth_db.count;
    auth_db_t old_db = s_auth_db;
    memset(&s_auth_db.devices[index], 0, sizeof(s_auth_db.devices[index]));
    memcpy(s_auth_db.devices[index].name, name, name_len + 1);
    memcpy(s_auth_db.devices[index].token_hash, hash, sizeof(hash));
    s_auth_db.count++;

    esp_err_t err = auth_db_save();
    if (err != ESP_OK) {
        s_auth_db = old_db;
        xSemaphoreGive(s_auth_mutex);
        return err;
    }

    memcpy(token_out, token, TOKEN_HEX_LEN + 1);
    ESP_LOGI(TAG, "Registered device: %s", name);
    xSemaphoreGive(s_auth_mutex);
    return ESP_OK;
}

esp_err_t auth_delete_all(const char *pin)
{
    if (pin == NULL || s_auth_mutex == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (strcmp(pin, ADMIN_PIN) != 0) {
        ESP_LOGW(TAG, "Delete-all rejected: invalid administrator PIN");
        return ESP_ERR_INVALID_ARG;
    }

    xSemaphoreTake(s_auth_mutex, portMAX_DELAY);
    auth_db_t old_db = s_auth_db;
    memset(&s_auth_db, 0, sizeof(s_auth_db));
    s_auth_db.magic = AUTH_DB_MAGIC;
    esp_err_t err = auth_db_save();
    if (err != ESP_OK) {
        s_auth_db = old_db;
        xSemaphoreGive(s_auth_mutex);
        return err;
    }
    ESP_LOGW(TAG, "All phone registrations deleted by administrator");
    xSemaphoreGive(s_auth_mutex);
    return ESP_OK;
}

/* ---------------- HTTP helpers ---------------- */

static esp_err_t send_error(httpd_req_t *req,
                            const char *status,
                            const char *message)
{
    httpd_resp_set_status(req, status);
    return httpd_resp_sendstr(req, message);
}

/* ---------------- Web page ---------------- */




static const char INDEX_HTML[] =
"<!DOCTYPE html><html lang='en'><head>"
"<meta charset='UTF-8'>"
"<meta name='viewport' content='width=device-width, initial-scale=1'>"
"<title>ESP32 Wi-Fi Door Lock</title>"
"<style>"
"body{font-family:Arial,sans-serif;max-width:440px;margin:30px auto;"
"padding:18px;background:#f4f6f8;color:#222;box-sizing:border-box}"
".card{background:#fff;padding:20px;margin:15px 0;border-radius:12px;"
"box-shadow:0 2px 8px #0001}"
"button{box-sizing:border-box;width:100%;padding:13px;margin:7px 0;"
"font-size:16px;border:0;border-radius:7px;color:white;cursor:pointer}"
".unlock{background:#b42318}.lock{background:#167647}"
".secondary{background:#2457a7}"
"button:disabled{opacity:.55;cursor:not-allowed}"
"#status{overflow-wrap:anywhere;line-height:1.5}"
".muted{color:#555;font-size:14px;overflow-wrap:anywhere}"
"</style></head><body>"

"<h2>ESP32 Wi-Fi Door Lock</h2>"

"<div class='card'>"
"<h3>Phone Registration</h3>"
"<p id='device'>Checking registration...</p>"
"<p class='muted' id='registrationInfo'>"
"Open the registration link provided by the administrator."
"</p>"
"</div>"

"<div class='card'>"
"<h3>Door Control</h3>"
"<button id='unlockButton' class='unlock' "
"onclick='setOutput(1)'>Unlock output</button>"
"<button id='lockButton' class='lock' "
"onclick='setOutput(0)'>Lock output</button>"
"<button class='secondary' onclick='forgetToken()'>"
"Forget registration on this phone</button>"
"<p id='status' role='status' aria-live='polite'></p>"
"</div>"

"<script>"
"const statusEl=document.getElementById('status');"

"function show(message){"
"statusEl.textContent=message;"
"}"

"function updateDevice(){"
"const token=localStorage.getItem('door_device_token');"
"const name=localStorage.getItem('door_device_name');"
"const deviceEl=document.getElementById('device');"
"const infoEl=document.getElementById('registrationInfo');"
"if(token&&/^[0-9a-f]{32}$/i.test(token)){"
"deviceEl.textContent='Registered phone: '+(name||'Phone');"
"infoEl.textContent='A device credential is saved in this browser.';"
"}else{"
"deviceEl.textContent='This phone is not registered.';"
"infoEl.textContent='Use the latest registration link from the administrator.';"
"}"
"}"

"function readRegistrationLink(){"
"const params=new URLSearchParams(window.location.search);"
"const token=params.get('token');"
"const name=params.get('name')||'Registered phone';"
"if(token!==null){"
"if(/^[0-9a-f]{32}$/i.test(token)){"
"localStorage.setItem('door_device_token',token);"
"localStorage.setItem('door_device_name',name);"
"show('Registration credential received and saved on this phone.');"
"}else{"
"show('Invalid registration link. Ask the administrator for a new link.');"
"}"
"window.history.replaceState({},document.title,window.location.pathname);"
"}"
"}"

"async function setOutput(state){"
"const token=localStorage.getItem('door_device_token');"
"if(!token||!/^[0-9a-f]{32}$/i.test(token)){"
"show('This phone has no valid registration credential. Open the latest administrator link.');"
"return;"
"}"
"const unlockButton=document.getElementById('unlockButton');"
"const lockButton=document.getElementById('lockButton');"
"unlockButton.disabled=true;"
"lockButton.disabled=true;"
"show(state===1?'Sending unlock request...':'Sending lock request...');"
"try{"
"const response=await fetch('/gpio?state='+state,{"
"method:'GET',"
"headers:{'X-Device-Token':token},"
"cache:'no-store'"
"});"
"const message=await response.text();"
"if(response.status===401){"
"show('Request rejected: registration credential is not accepted. Ask the administrator to register this phone again.');"
"}else if(!response.ok){"
"show('Request failed ('+response.status+'): '+message);"
"}else{"
"show(message);"
"}"
"}catch(error){"
"show('Could not contact the ESP32. Check that this phone is connected to its Wi-Fi network.');"
"}finally{"
"unlockButton.disabled=false;"
"lockButton.disabled=false;"
"}"
"}"

"function forgetToken(){"
"localStorage.removeItem('door_device_token');"
"localStorage.removeItem('door_device_name');"
"updateDevice();"
"show('Credential removed from this browser. Ask the administrator to issue a new registration link if needed.');"
"}"

"readRegistrationLink();"
"updateDevice();"
"</script></body></html>";


static esp_err_t root_get_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(req, INDEX_HTML, HTTPD_RESP_USE_STRLEN);
}

/* ---------------- Authorized GPIO endpoint ---------------- */

static esp_err_t gpio_handler(httpd_req_t *req)
{
    char token[TOKEN_HEX_LEN + 1];

    if (httpd_req_get_hdr_value_str(
            req, "X-Device-Token", token, sizeof(token)) != ESP_OK) {
        ESP_LOGW(TAG, "GPIO request rejected: missing token");
        (void)sos_trigger();
          return send_error(req, "401 Unauthorized",
                          "Device credential required");
    }

    if (!token_matches(token)) {
        ESP_LOGW(TAG, "GPIO request rejected: invalid token");
         (void)sos_trigger();
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
    config.max_uri_handlers = 4;

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

    httpd_uri_t gpio_uri = {
        .uri = "/gpio",
        .method = HTTP_GET,
        .handler = gpio_handler,
        .user_ctx = NULL
    };

    httpd_register_uri_handler(s_http_server, &root_uri);
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
     
    err = sos_init();

    if (err != ESP_OK) {
      ESP_LOGE(TAG, "SOS initialization failed: %s",
             esp_err_to_name(err));
             return err;
     }

    gpio_set_level(DOOR_GPIO, 0);

    /* Protect the shared registration database across both HTTP servers. */
    s_auth_mutex = xSemaphoreCreateMutex();
    if (s_auth_mutex == NULL) {
        ESP_LOGE(TAG, "Could not create authentication mutex");
        return ESP_ERR_NO_MEM;
    }

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
