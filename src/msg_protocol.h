#ifndef SRC_MSG_PROTOCOL_H
#define SRC_MSG_PROTOCOL_H

/**
 * msg_protocol.h - Message protocol interface
 * 
 * Handles formatting and parsing of telemetry messages
 * in JSON format for IoT communication
 * 
 * Author: Ryan Tobin
 * Date: 2025
 */

#include <stdint.h>
#include <stddef.h>
#include "error.h"
#include "config.h"

/* Message types */
typedef enum {
    MSG_TYPE_TELEMETRY = 0x01,      /* Telemetry data */
    MSG_TYPE_COMMAND = 0x02,        /* Command message */
    MSG_TYPE_RESPONSE = 0x03,       /* Response message */
    MSG_TYPE_ERROR = 0x04           /* Error message */
} msg_type_t;

/* Telemetry data structure */
typedef struct {
    uint32_t timestamp;             /* Unix timestamp */
    float temperature;              /* Temperature in Celsius */
    float humidity;                 /* Humidity percentage */
    float pressure;                 /* Pressure in hPa */
    uint32_t battery_mv;            /* Battery voltage in mV */
    uint32_t uptime_sec;            /* Device uptime in seconds */
} telemetry_data_t;

/* Command structure */
typedef struct {
    uint32_t command_id;            /* Command ID */
    char command[64];               /* Command string */
    char params[128];               /* Parameters */
} command_data_t;

/* Response structure */
typedef struct {
    uint32_t request_id;            /* Original request ID */
    int32_t status_code;            /* Status code */
    char message[256];              /* Response message */
} response_data_t;

/* Generic message structure */
typedef struct {
    uint32_t msg_id;                /* Message ID */
    msg_type_t type;                /* Message type */
    union {
        telemetry_data_t telemetry;
        command_data_t command;
        response_data_t response;
    } data;
} message_t;

/**
 * Format telemetry message to JSON
 * 
 * @param telemetry Telemetry data
 * @param buffer Output buffer
 * @param buffer_size Buffer size
 * @param written Bytes written (output)
 * @return Error code
 */
error_code_t msg_format_telemetry(const telemetry_data_t *telemetry,
                                  char *buffer, size_t buffer_size,
                                  size_t *written);

/**
 * Format command message to JSON
 * 
 * @param command Command data
 * @param buffer Output buffer
 * @param buffer_size Buffer size
 * @param written Bytes written (output)
 * @return Error code
 */
error_code_t msg_format_command(const command_data_t *command,
                               char *buffer, size_t buffer_size,
                               size_t *written);

/**
 * Format response message to JSON
 * 
 * @param response Response data
 * @param buffer Output buffer
 * @param buffer_size Buffer size
 * @param written Bytes written (output)
 * @return Error code
 */
error_code_t msg_format_response(const response_data_t *response,
                                char *buffer, size_t buffer_size,
                                size_t *written);

/**
 * Parse JSON message
 * 
 * @param json JSON string
 * @param json_len JSON string length
 * @param message Parsed message (output)
 * @return Error code
 */
error_code_t msg_parse_json(const char *json, size_t json_len,
                           message_t *message);

/**
 * Validate message
 * 
 * @param message Message to validate
 * @return Error code
 */
error_code_t msg_validate(const message_t *message);

/**
 * Generate message ID
 * 
 * @return New message ID
 */
uint32_t msg_generate_id(void);

/**
 * Get current timestamp
 * 
 * @return Unix timestamp
 */
uint32_t msg_get_timestamp(void);

#endif /* SRC_MSG_PROTOCOL_H */