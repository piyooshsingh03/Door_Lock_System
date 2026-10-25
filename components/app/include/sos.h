
#ifndef SOS_H
#define SOS_H

#include "esp_err.h"

/**
 * @brief Initialize the SOS GPIO and timer.
 *
 * GPIO4 is active LOW:
 * LOW  = SOS active
 * HIGH = SOS inactive
 */
esp_err_t sos_init(void);

/**
 * @brief Activate SOS for 3 seconds.
 *
 * Does not block the HTTP server.
 */
esp_err_t sos_trigger(void);

#endif
