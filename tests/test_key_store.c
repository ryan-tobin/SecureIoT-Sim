/**
 * test_key_store.c - Key store unit tests
 * 
 * Tests for the simulated flash-based key storage module
 * 
 * Author: Ryan Tobin
 * Date: 2025
 */

/* Disable unused variable warnings for test assertions */
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#endif

#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "../src/key_store.h"
#include "../src/error.h"

/**
 * Test key store initialization
 */
static void test_keystore_init(void)
{
    keystore_t store;
    error_code_t ret;
    
    printf("Testing keystore_init...\n");
    
    ret = keystore_init(&store);
    assert(ret == ERR_OK);
    assert(store.magic == KEYSTORE_MAGIC);
    assert(store.version == 1);
    assert(store.num_entries == 0);
    
    printf("  PASS\n");
}

/**
 * Test key store clear
 */
static void test_keystore_clear(void)
{
    keystore_t store;
    error_code_t ret;
    
    printf("Testing keystore_clear...\n");
    
    ret = keystore_init(&store);
    assert(ret == ERR_OK);
    
    ret = keystore_clear(&store);
    assert(ret == ERR_OK);
    assert(store.num_entries == 0);
    
    printf("  PASS\n");
}

/**
 * Test key store integrity check
 */
static void test_keystore_verify_integrity(void)
{
    keystore_t store;
    error_code_t ret;
    
    printf("Testing keystore_verify_integrity...\n");
    
    ret = keystore_init(&store);
    assert(ret == ERR_OK);
    
    ret = keystore_verify_integrity(&store);
    assert(ret == ERR_OK);
    
    /* Corrupt magic number */
    store.magic = 0xDEADBEEF;
    ret = keystore_verify_integrity(&store);
    assert(ret == ERR_KEYSTORE_NOT_FOUND);
    
    printf("  PASS\n");
}

/**
 * Test parameter validation
 */
static void test_parameter_validation(void)
{
    error_code_t ret;
    
    printf("Testing parameter validation...\n");
    
    ret = keystore_init(NULL);
    assert(ret == ERR_INVALID_PARAM);
    
    ret = keystore_verify_integrity(NULL);
    assert(ret == ERR_INVALID_PARAM);
    
    printf("  PASS\n");
}

/**
 * Main test runner
 */
int main(void)
{
    printf("=== Key Store Unit Tests ===\n");
    
    test_parameter_validation();
    test_keystore_init();
    test_keystore_clear();
    test_keystore_verify_integrity();
    
    /* TODO: Add more tests as functionality is implemented */
    
    printf("\nAll tests passed!\n");
    return 0;
}

#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif