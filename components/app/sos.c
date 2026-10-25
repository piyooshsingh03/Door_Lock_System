
#include "sos.h"

#include "driver/gpio.h"
#include "esp_log.h"
#include "esp_timer.h"

#define TAG             "SOS"
#define SOS_GPIO        GPIO_NUM_4
#define SOS_DURATION_US 3000000LL

static esp_timer_handle_t s_sos_timer = NULL;

static void sos_timer_callback(void *arg)
{
    (void)arg;

    gpio_set_level(SOS_GPIO, 1);

    ESP_LOGI(TAG, "SOS inactive: GPIO4 returned HIGH");
}

esp_err_t sos_init(void)
{
    gpio_config_t config = {
        .pin_bit_mask = (1ULL << SOS_GPIO),
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE
    };

    esp_err_t err = gpio_config(&config);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "GPIO configuration failed: %s",
                 esp_err_to_name(err));
        return err;
    }

    /* Active-low output: HIGH means inactive. */
    err = gpio_set_level(SOS_GPIO, 1);
    if (err != ESP_OK) {
        return err;
    }

    const esp_timer_create_args_t timer_args = {
        .callback = sos_timer_callback,
        .arg = NULL,
        .dispatch_method = ESP_TIMER_TASK,
        .name = "sos_reset"
    };

    err = esp_timer_create(&timer_args, &s_sos_timer);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Timer creation failed: %s",
                 esp_err_to_name(err));
        return err;
    }

    ESP_LOGI(TAG, "SOS initialized on GPIO4, active LOW");
    return ESP_OK;
}

esp_err_t sos_trigger(void)
{
    if (s_sos_timer == NULL) {
        ESP_LOGE(TAG, "SOS is not initialized");
        return ESP_ERR_INVALID_STATE;
    }

    /*
     * Restart the 3-second countdown if SOS is already active.
     */
    esp_err_t err = esp_timer_stop(s_sos_timer);

    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "Could not stop previous timer: %s",
                 esp_err_to_name(err));
        return err;
    }

    err = gpio_set_level(SOS_GPIO, 0);
    if (err != ESP_OK) {
        return err;
    }

    ESP_LOGW(TAG, "SOS activated: unauthorized request");

    err = esp_timer_start_once(s_sos_timer, SOS_DURATION_US);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Could not start SOS timer: %s",
                 esp_err_to_name(err));

        /* Avoid leaving SOS active indefinitely. */
        gpio_set_level(SOS_GPIO, 1);
        return err;
    }

    return ESP_OK;
}
