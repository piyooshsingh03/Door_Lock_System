
idf_component_register(
    SRCS
        "app.c"
        "setting.c"
        "sos.c"
    INCLUDE_DIRS
        "include"
    REQUIRES
        wifi_manager
        esp_http_server
        esp_driver_gpio
        esp_timer
        nvs_flash
        espressif__cjson
        mbedtls
        esp_hw_support
)
