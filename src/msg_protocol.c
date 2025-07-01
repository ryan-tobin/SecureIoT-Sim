/**
 * msg_protocol.c - Message protocol implementation
 * 
 * Handles formatting and parsing of telemetry messages
 * in JSON format for IoT communication
 * 
 * Author: Ryan Tobin
 * Date: 2025
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "msg_protocol.h"
#include "config.h"
#include "error.h"

/* Message ID counter */
static uint32_t g_msg_id_counter = 0;

/**
 * Format telemetry message to JSON
 */
error_code_t msg_format_telemetry(const telemetry_data_t *telemetry,
                                  char *buffer, size_t buffer_size,
                                  size_t *written)
{
    CHECK_PARAM(telemetry);
    CHECK_PARAM(buffer);
    CHECK_PARAM(written);
    
    int ret = snprintf(buffer, buffer_size,
        "{"
        "\"type\":\"telemetry\","
        "\"timestamp\":%u,"
        "\"data\":{"
        "\"temperature\":%.2f,"
        "\"humidity\":%.2f,"
        "\"pressure\":%.2f,"
        "\"battery_mv\":%u,"
        "\"uptime_sec\":%u"
        "}"
        "}",
        telemetry->timestamp,
        telemetry->temperature,
        telemetry->humidity,
        telemetry->pressure,
        telemetry->battery_mv,
        telemetry->uptime_sec
    );
    
    if (ret < 0 || (size_t)ret >= buffer_size) {
        return ERR_BUFFER_TOO_SMALL;
    }
    
    *written = (size_t)ret;
    return ERR_OK;
}

/**
 * Format command message to JSON
 */
error_code_t msg_format_command(const command_data_t *command,
                               char *buffer, size_t buffer_size,
                               size_t *written)
{
    CHECK_PARAM(command);
    CHECK_PARAM(buffer);
    CHECK_PARAM(written);
    
    /* TODO: Implement command formatting */
    
    return ERR_NOT_IMPLEMENTED;
}

/**
 * Format response message to JSON
 */
error_code_t msg_format_response(const response_data_t *response,
                                char *buffer, size_t buffer_size,
                                size_t *written)
{
    CHECK_PARAM(response);
    CHECK_PARAM(buffer);
    CHECK_PARAM(written);
    
    /* TODO: Implement response formatting */
    
    return ERR_NOT_IMPLEMENTED;
}

/**
 * Parse JSON message
 */
error_code_t msg_parse_json(const char *json, size_t json_len,
                           message_t *message)
{
    CHECK_PARAM(json);
    CHECK_PARAM(message);
    
    /* TODO: Implement JSON parsing */
    /* Note: In production, use a proper JSON parser */
    
    return ERR_NOT_IMPLEMENTED;
}

/**
 * Validate message
 */
error_code_t msg_validate(const message_t *message)
{
    CHECK_PARAM(message);
    
    /* Check message type */
    if (message->type < MSG_TYPE_TELEMETRY || message->type > MSG_TYPE_ERROR) {
        return ERR_MSG_INVALID_FORMAT;
    }
    
    /* TODO: Add more validation */
    
    return ERR_OK;
}

/**
 * Generate message ID
 */
uint32_t msg_generate_id(void)
{
    return ++g_msg_id_counter;
}

/**
 * Get current timestamp
 */
uint32_t msg_get_timestamp(void)
{
    return (uint32_t)time(NULL);
}