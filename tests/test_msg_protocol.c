/**
 * test_msg_protocol.c - Message protocol unit tests
 * 
 * Tests for JSON message formatting and parsing
 * 
 * Author: Ryan Tobin
 * Date: 2025
 */
/* Disable unused variable warnings for test assertions */
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#endif

#define _POSIX_C_SOURCE 200809L  /* For nanosleep */

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <unistd.h>
#endif

#include "../src/msg_protocol.h"
#include "../src/error.h"

/**
 * Test telemetry message formatting
 */
static void test_format_telemetry(void)
{
    telemetry_data_t telemetry;
    char buffer[MAX_MSG_SIZE];
    size_t written;
    error_code_t ret;
    
    printf("Testing msg_format_telemetry...\n");
    
    /* Prepare test data */
    telemetry.timestamp = 1234567890;
    telemetry.temperature = 22.5f;
    telemetry.humidity = 65.3f;
    telemetry.pressure = 1013.25f;
    telemetry.battery_mv = 3300;
    telemetry.uptime_sec = 3600;
    
    /* Format message */
    ret = msg_format_telemetry(&telemetry, buffer, sizeof(buffer), &written);
    assert(ret == ERR_OK);
    assert(written > 0);
    assert(written < sizeof(buffer));
    
    /* Verify JSON contains expected fields */
    assert(strstr(buffer, "\"type\":\"telemetry\"") != NULL);
    assert(strstr(buffer, "\"temperature\":22.50") != NULL);
    assert(strstr(buffer, "\"humidity\":65.30") != NULL);
    
    printf("  Generated JSON (%zu bytes): %s\n", written, buffer);
    printf("  PASS\n");
}

/**
 * Test buffer overflow handling
 */
static void test_buffer_overflow(void)
{
    telemetry_data_t telemetry;
    char small_buffer[50];  /* Too small for full message */
    size_t written;
    error_code_t ret;
    
    printf("Testing buffer overflow handling...\n");
    
    /* Prepare test data */
    telemetry.timestamp = 1234567890;
    telemetry.temperature = 22.5f;
    telemetry.humidity = 65.3f;
    telemetry.pressure = 1013.25f;
    telemetry.battery_mv = 3300;
    telemetry.uptime_sec = 3600;
    
    /* Try to format message in small buffer */
    ret = msg_format_telemetry(&telemetry, small_buffer, sizeof(small_buffer), &written);
    assert(ret == ERR_BUFFER_TOO_SMALL);
    
    printf("  PASS\n");
}

/**
 * Test message ID generation
 */
static void test_generate_id(void)
{
    uint32_t id1, id2, id3;
    
    printf("Testing msg_generate_id...\n");
    
    id1 = msg_generate_id();
    id2 = msg_generate_id();
    id3 = msg_generate_id();
    
    /* IDs should be sequential */
    assert(id2 == id1 + 1);
    assert(id3 == id2 + 1);
    
    printf("  Generated IDs: %u, %u, %u\n", id1, id2, id3);
    printf("  PASS\n");
}

/**
 * Test timestamp generation
 */
static void test_get_timestamp(void)
{
    uint32_t ts1, ts2;
    
    printf("Testing msg_get_timestamp...\n");
    
    ts1 = msg_get_timestamp();
    
    /* Timestamp should be reasonable */
    assert(ts1 > 0);
    
    /* Wait a bit and check again */
    #ifdef _WIN32
        Sleep(1100);  /* Windows */
    #else
        struct timespec req = {1, 100000000};  /* 1.1 seconds */
        nanosleep(&req, NULL);
    #endif
    
    ts2 = msg_get_timestamp();
    assert(ts2 > ts1);
    
    printf("  Timestamps: %u, %u\n", ts1, ts2);
    printf("  PASS\n");
}

/**
 * Test parameter validation
 */
static void test_parameter_validation(void)
{
    telemetry_data_t telemetry;
    char buffer[MAX_MSG_SIZE];
    size_t written;
    error_code_t ret;
    
    printf("Testing parameter validation...\n");
    
    /* NULL telemetry */
    ret = msg_format_telemetry(NULL, buffer, sizeof(buffer), &written);
    assert(ret == ERR_INVALID_PARAM);
    
    /* NULL buffer */
    ret = msg_format_telemetry(&telemetry, NULL, sizeof(buffer), &written);
    assert(ret == ERR_INVALID_PARAM);
    
    /* NULL written */
    ret = msg_format_telemetry(&telemetry, buffer, sizeof(buffer), NULL);
    assert(ret == ERR_INVALID_PARAM);
    
    printf("  PASS\n");
}

/**
 * Main test runner
 */
int main(void)
{
    printf("=== Message Protocol Unit Tests ===\n");
    
    test_parameter_validation();
    test_format_telemetry();
    test_buffer_overflow();
    test_generate_id();
    test_get_timestamp();
    
    /* TODO: Add tests for parsing and other message types */
    
    printf("\nAll tests passed!\n");
    return 0;
}

#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif