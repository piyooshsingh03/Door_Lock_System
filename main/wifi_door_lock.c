
#include <stdio.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_log.h"
#include "esp_err.h"
#include "nvs_flash.h"

#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_http_server.h"

#include "driver/gpio.h"

#define LED_GPIO       GPIO_NUM_2
#define WIFI_SSID      "ESP32_DoorLock"
#define WIFI_PASSWORD  "DoorDemo123"

static const char *TAG = "DOOR_LOCK";

static bool led_state = false;

/* HTTP page shown in the browser */
static const char *web_page =
    "<!DOCTYPE html>"
    "<html><head><meta name='viewport' "
    "content='width=device-width, initial-scale=1'>"
    "<title>ESP32 Door Lock</title></head>"
    "<body style='font-family:Arial;text-align:center;'>"
    "<h2>ESP32 Wi-Fi Door Lock</h2>"
    "<p>GPIO control demonstration</p>"
    "<button onclick=\"control('1')\">UNLOCK / ON</button>"
    "<br><br>"
    "<button onclick=\"control('0')\">LOCK / OFF</button>"
    "<p id='status'>Ready</p>"
    "<script>"
    "async function control(state) {"
    " try {"
    "  const r = await fetch('/gpio?state=' + state);"
    "  document.getElementById('status').innerText = "
    "    await r.text();"
    " } catch(e) {"
    "  document.getElementById('status').innerText = "
    "    'Request failed';"
    " }"
    "}"
    "</script></body></html>";

/* Send the control webpage */
static esp_err_t root_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(req, web_page, HTTPD_RESP_USE_STRLEN);
}

/* Receive GPIO commands */
static esp_err_t gpio_handler(httpd_req_t *req)
{
    char query[32];
    char state[8];

    if (httpd_req_get_url_query_str(
            req, query, sizeof(query)) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                            "Missing state parameter");
        return ESP_OK;
    }

    if (httpd_query_key_value(
            query, "state", state, sizeof(state)) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                            "Missing state parameter");
        return ESP_OK;
    }

    if (strcmp(state, "1") == 0) {
        led_state = true;
    } else if (strcmp(state, "0") == 0) {
        led_state = false;
    } else {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                            "Use state=1 or state=0");
        return ESP_OK;
    }

    gpio_set_level(LED_GPIO, led_state ? 1 : 0);

    ESP_LOGI(TAG, "GPIO %d set to %d",
             (int)LED_GPIO, led_state ? 1 : 0);

    httpd_resp_set_type(req, "text/plain");
    return httpd_resp_send(
        req, led_state ? "GPIO ON" : "GPIO OFF",
        HTTPD_RESP_USE_STRLEN);
}

/* Start the HTTP server */
static httpd_handle_t start_webserver(void)
{
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    httpd_handle_t server = NULL;

    ESP_ERROR_CHECK(httpd_start(&server, &config));

    httpd_uri_t root_uri = {
        .uri = "/",
        .method = HTTP_GET,
        .handler = root_handler,
        .user_ctx = NULL
    };

    httpd_uri_t gpio_uri = {
        .uri = "/gpio",
        .method = HTTP_GET,
        .handler = gpio_handler,
        .user_ctx = NULL
    };

    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &root_uri));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &gpio_uri));

    ESP_LOGI(TAG, "HTTP server started on port 80");
    return server;
}

/* Configure the ESP32 as a Wi-Fi access point */
static void wifi_init_softap(void)
{
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_ap();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    wifi_config_t wifi_config = {0};

    strcpy((char *)wifi_config.ap.ssid, WIFI_SSID);
    strcpy((char *)wifi_config.ap.password, WIFI_PASSWORD);

    wifi_config.ap.ssid_len = strlen(WIFI_SSID);
    wifi_config.ap.channel = 1;
    wifi_config.ap.max_connection = 1;
    wifi_config.ap.authmode = WIFI_AUTH_WPA2_PSK;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(
        WIFI_IF_AP, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "Wi-Fi hotspot started");
    ESP_LOGI(TAG, "SSID: %s", WIFI_SSID);
    ESP_LOGI(TAG, "Connect to http://192.168.4.1");
}

void app_main(void)
{
    esp_err_t ret = nvs_flash_init();

    if (ret == ESP_ERR_NVS_NO_FREE_PAGES ||
        ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }

    ESP_ERROR_CHECK(ret);

    /* Configure GPIO as an output */
    gpio_config_t io_conf = {
        .pin_bit_mask = 1ULL << LED_GPIO,
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE
    };

    ESP_ERROR_CHECK(gpio_config(&io_conf));
    ESP_ERROR_CHECK(gpio_set_level(LED_GPIO, 0));

    wifi_init_softap();
    start_webserver();

    ESP_LOGI(TAG, "Door lock demo is ready");
}

