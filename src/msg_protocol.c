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
#include <ctype.h>
#include <stdarg.h>

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
    
    int ret = snprintf(buffer, buffer_size,
        "{"
        "\"type\":\"command\","
        "\"id\":%u,"
        "\"command\":\"%s\","
        "\"params\":\"%s\""
        "}",
        command->command_id,
        command->command,
        command->params
    );

    if (ret < 0 || (size_t)ret >= buffer_size) {
        return ERR_BUFFER_TOO_SMALL;
    }

    *written = (size_t)ret;
    return ERR_OK;
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
    
    int ret = snprintf(buffer, buffer_size,
        "{"
        "\"type\":\"response\","
        "\"request_id\":%u,"
        "\"status\":%d,"
        "\"message\":\"%s\""
        "}",
        response->request_id,
        response->status_code,
        response->message
    );

    if (ret < 0 || (size_t)ret >= buffer_size) {
        return ERR_BUFFER_TOO_SMALL;
    }
    
    *written = (size_t)ret;
    return ERR_NOT_IMPLEMENTED;
}

/**
 * Find a JSON field in a string
 * Returns pointer to the value after the colon, or NULL if not fund
 */
static const char* find_json_field(const char *json, const char *field)
{
    char search_pattern[128];
    snprintf(search_pattern, sizeof(search_pattern), "\%s\"", field);

    const char *pos = strstr(json, search_pattern);
    if (pos == NULL) {
        return NULL;
    }

    /* Find the colon */
    pos = strchr(pos, ':');
    if (pos == NULL) {
        return NULL;
    }

    /* Skip colon and whitespace */
    pos++;
    while (*pos && isspace(*pos)) {
        pos++;
    }

    return pos;
}

/**
 * Extract a string value from JSON
 * Returns 0 on sucess, -1 on error
 */
static int extract_json_string(const char *json, const char *field, char *output, size_t max_len)
{
    const char *value = find_json_field(json, field);
    if (value == NULL || *value != '"') {
        return -1;
    }

    /* skip opening quote */
    value++;

    /* copy until closing quote */
    size_t i = 0;
    while (*value && *value != '"' && i < max_len - 1) {
        output[i++] = *value++;
    }
    output[i] = '\0';

    return (*value == '"') ? 0 : -1;
}

/**
 * Extract a number value from JSON
 * Returns 0 on sucess, -1 on error
 */
static int extract_json_number(const char *json, const char *field, uint32_t *output)
{
    const char *value = find_json_field(json, field);
    if (value == NULL) {
        return -1;
    }

    char *endptr;
    unsigned long num = strtoul(value, &endptr, 10);
    if (endptr == value) {
        return -1;
    }

    *output = (uint32_t)num;
    return 0;
}

/**
 * Extract a float value from JSON
 * Returns 0 on success, -1 on error
 */
static int extract_json_float(const char *json, const char *field, float *output)
{
    const char *value = find_json_field(json,field);
    if (value == NULL) {
        return -1;
    }

    char *endptr;
    float num = strtof(value, &endptr);
    if (endptr == value) {
        return -1;
    }

    *output = num;
    return 0;
}


/**
 * Parse JSON message
 */
error_code_t msg_parse_json(const char *json, size_t json_len,
                           message_t *message)
{
    CHECK_PARAM(json);
    CHECK_PARAM(message);
    
    (void)json_len; 

    /* clear output */
    memset(message, 0, sizeof(message_t));

    /* extract message type */
    char type_str[32];
    if (extract_json_string(json, "type", type_str, sizeof(type_str)) != 0) {
        return ERR_MSG_INVALID_FORMAT;
    }

    /* determine msg type */
    if (strcmp(type_str, "telemetry") == 0) {
        message->type = MSG_TYPE_TELEMETRY;

        telemetry_data_t *telemetry = &message->data.telemetry;

        if (extract_json_number(json, "timestamp", &telemetry->timestamp) != 0) {
            telemetry->timestamp = msg_get_timestamp();
        }

        /* look for nested data object */
        const char *data_obj = find_json_field(json, "data");
        if (data_obj != NULL) {
            extract_json_float(data_obj, "temperature", &telemetry->temperature);
            extract_json_float(data_obj, "humidity", &telemetry->humidity);
            extract_json_float(data_obj, "pressure", &telemetry->pressure);
            extract_json_number(data_obj, "battery_mv", &telemetry->battery_mv);
            extract_json_number(data_obj, "uptime_sec", &telemetry->uptime_sec);
        }
    }
    else if (strcmp(type_str, "command") == 0) {
        message->type = MSG_TYPE_COMMAND;

        /* extract command fields */
        command_data_t *command = &message->data.command;
        extract_json_number(json, "id", &command->command_id);
        extract_json_string(json, "command", command->command, sizeof(command->command));
        extract_json_string(json, "params", command->params, sizeof(command->params));
    }
    else if (strcmp(type_str, "response") == 0) {
        message->type = MSG_TYPE_RESPONSE;
        
        response_data_t *response = &message->data.response;
        extract_json_number(json, "request_id", &response->request_id);
        
        int32_t status;
        if (extract_json_number(json, "status", (uint32_t*)&status) == 0) {
            response->status_code = status;
        }
        
        extract_json_string(json, "message", response->message, 
                           sizeof(response->message));
    }

    else if (strcmp(type_str, "error") == 0) {
        message->type = MSG_TYPE_ERROR;
    }
    else {
        return ERR_MSG_INVALID_FORMAT;
    }

    /* extract common fields */
    extract_json_number(json, "id", &message->msg_id);
    
    return ERR_OK;
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
    
    /* validate based on type */
    switch (message->type) {
        case MSG_TYPE_TELEMETRY:
            if (message->data.telemetry.temperature < -100.0f || message->data.telemetry.temperature > 100.0f) {
                return ERR_MSG_INVALID_FORMAT;
            }
            if (message->data.telemetry.humidity < 0.0f || message->data.telemetry.humidity > 100.0f) {
                return ERR_MSG_INVALID_FORMAT;
            }
            break;
        
        case MSG_TYPE_COMMAND:
            if (strlen(message->data.command.command) == 0) {
                return ERR_MSG_INVALID_FORMAT;
            }
            break;

        case MSG_TYPE_RESPONSE:
            if (strlen(message->data.response.message) == 0) {
                return ERR_MSG_INVALID_FORMAT;
            }
            break;

        case MSG_TYPE_ERROR:
            break;

        default:
            return ERR_MSG_INVALID_FORMAT;
    }
    
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