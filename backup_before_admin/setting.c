
#include <string.h>

#include "esp_log.h"
#include "esp_http_server.h"
#include "esp_err.h"

#include "setting.h"

static const char *TAG = "SETTING";
static httpd_handle_t settings_server = NULL;

static esp_err_t settings_root_handler(httpd_req_t *req)
{
    static const char page[] =
        "<!DOCTYPE html>"
        "<html><head><meta name='viewport' "
        "content='width=device-width,initial-scale=1'>"
        "<title>Door Lock Admin</title></head>"
        "<body style='font-family:Arial;max-width:480px;"
        "margin:40px auto;padding:16px'>"
        "<h2>Door Lock - Admin Settings</h2>"
        "<p>Administrator settings page</p>"
        "<p>Phone registration and delete-all functions "
        "will be connected in the next step.</p>"
        "</body></html>";

    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(req, page, HTTPD_RESP_USE_STRLEN);
}

esp_err_t setting_start(void)
{
    if (settings_server != NULL) {
        return ESP_OK;
    }

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();

    /* Use a different TCP port from the phone-control server. */
    config.server_port = 8080;
    config.ctrl_port = 32769;

    esp_err_t err = httpd_start(&settings_server, &config);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start settings server: %s",
                 esp_err_to_name(err));
        return err;
    }

    httpd_uri_t root_uri = {
        .uri = "/",
        .method = HTTP_GET,
        .handler = settings_root_handler,
        .user_ctx = NULL
    };

    err = httpd_register_uri_handler(settings_server, &root_uri);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to register settings page: %s",
                 esp_err_to_name(err));
        httpd_stop(settings_server);
        settings_server = NULL;
        return err;
    }

    ESP_LOGI(TAG, "Admin page started on port 8080");
    return ESP_OK;
}
