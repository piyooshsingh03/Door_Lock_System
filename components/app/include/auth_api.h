#ifndef AUTH_API_H
#define AUTH_API_H

#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

/* Shared by the phone-control server and administrator server. */
esp_err_t auth_get_status(uint32_t *registered, uint32_t *maximum);
esp_err_t auth_register_device(const char *name, const char *pin,
                               char *token_out, size_t token_out_size);
esp_err_t auth_delete_all(const char *pin);

#endif
