#include "nvs_reset.h"

#include "nvs_flash.h"
#include "esp_log.h"

static const char *TAG = "NVS_RESET";

esp_err_t erase_nvs_storage(void)
{
    ESP_LOGW(TAG, "Erasing the entire NVS partition!");

    esp_err_t err = nvs_flash_erase();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "NVS erase failed: %s",
                 esp_err_to_name(err));
        return err;
    }

    err = nvs_flash_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "NVS reinitialization failed: %s",
                 esp_err_to_name(err));
        return err;
    }

    ESP_LOGW(TAG, "NVS erased and initialized successfully");
    return ESP_OK;
}
