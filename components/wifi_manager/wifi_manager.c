
#include <string.h>

#include "wifi_manager.h"

#include "esp_event.h"
#include "esp_netif.h"
#include "esp_netif_ip_addr.h"
#include "esp_wifi.h"
#include "esp_mac.h"
#include "esp_log.h"

#define WIFI_SSID      "Door_number_5"
#define WIFI_PASSWORD  "Pk@system"

static const char *TAG = "WIFI_MANAGER";

static void wifi_event_handler(
    void *arg,
    esp_event_base_t event_base,
    int32_t event_id,
    void *event_data)
{
    if (event_base == WIFI_EVENT) {

        if (event_id == WIFI_EVENT_AP_STACONNECTED) {

            wifi_event_ap_staconnected_t *event =
                (wifi_event_ap_staconnected_t *)event_data;

            ESP_LOGI(TAG, "Device connected");
            ESP_LOGI(TAG, "MAC: " MACSTR,
                     MAC2STR(event->mac));

        } else if (event_id == WIFI_EVENT_AP_STADISCONNECTED) {

            wifi_event_ap_stadisconnected_t *event =
                (wifi_event_ap_stadisconnected_t *)event_data;

            ESP_LOGI(TAG, "Device disconnected");
            ESP_LOGI(TAG, "MAC: " MACSTR,
                     MAC2STR(event->mac));
        }

    } else if (event_base == IP_EVENT &&
               event_id == IP_EVENT_AP_STAIPASSIGNED) {

        ip_event_ap_staipassigned_t *event =
            (ip_event_ap_staipassigned_t *)event_data;

        ESP_LOGI(TAG, "IP assigned to device");
        ESP_LOGI(TAG, "MAC: " MACSTR,
                 MAC2STR(event->mac));
        ESP_LOGI(TAG, "IP: " IPSTR,
                 IP2STR(&event->ip));
    }
}


esp_err_t wifi_manager_start(void)
{
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    esp_netif_create_default_wifi_ap();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_register(
        WIFI_EVENT,
        WIFI_EVENT_AP_STACONNECTED,
        wifi_event_handler,
        NULL));

    ESP_ERROR_CHECK(esp_event_handler_register(
        WIFI_EVENT,
        WIFI_EVENT_AP_STADISCONNECTED,
        wifi_event_handler,
        NULL));

ESP_ERROR_CHECK(
    esp_event_handler_register(
        IP_EVENT,
        IP_EVENT_AP_STAIPASSIGNED,
        wifi_event_handler,
        NULL
    )
);

    wifi_config_t wifi_config = {0};

    memcpy(wifi_config.ap.ssid, WIFI_SSID, strlen(WIFI_SSID));
    memcpy(wifi_config.ap.password, WIFI_PASSWORD,
           strlen(WIFI_PASSWORD));

    wifi_config.ap.ssid_len = strlen(WIFI_SSID);
    wifi_config.ap.channel = 1;
    wifi_config.ap.max_connection = 2;
    wifi_config.ap.authmode = WIFI_AUTH_WPA2_PSK;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));

    ESP_ERROR_CHECK(esp_wifi_set_config(
        WIFI_IF_AP, &wifi_config));

    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "Hotspot started: %s", WIFI_SSID);
    ESP_LOGI(TAG, "Web interface: http://192.168.4.1");

    return ESP_OK;
}
