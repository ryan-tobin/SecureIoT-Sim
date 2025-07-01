#ifndef SRC_KEY_STORE_H
#define SRC_KEY_STORE_H

/**
 * key_store.h - Simulated flash-based key storage
 * 
 * Emulates embedded flash storage for device certificates and keys
 * with static memory allocation
 * 
 * Author: Ryan Tobin
 * Date: 2025
 */
#include <stdint.h>
#include <stddef.h>
#include "error.h"
#include "config.h"

/* Key store entry types */
typedef enum {
    KEYSTORE_TYPE_EMPTY = 0,        /* Empty slot */
    KEYSTORE_TYPE_CERTIFICATE = 1,  /* X.509 certificate */
    KEYSTORE_TYPE_PRIVATE_KEY = 2,  /* Private key */
    KEYSTORE_TYPE_PUBLIC_KEY = 3,   /* Public key */
    KEYSTORE_TYPE_CA_CERT = 4       /* CA certificate */
} keystore_entry_type_t;

/* Key store entry */
typedef struct {
    uint32_t id;                    /* Entry ID */
    keystore_entry_type_t type;     /* Entry type */
    uint32_t size;                  /* Data size */
    uint8_t data[MAX_CERT_SIZE];    /* Certificate/key data */
    uint32_t checksum;              /* CRC32 checksum */
} keystore_entry_t;

/* Key store context */
typedef struct {
    uint32_t magic;                 /* Magic number for validation */
    uint32_t version;               /* Store format version */
    uint32_t num_entries;           /* Number of entries */
    keystore_entry_t entries[KEYSTORE_MAX_ENTRIES];
} keystore_t;

/**
 * Initialize key store
 * 
 * @param store Key store instance
 * @return Error code
 */
error_code_t keystore_init(keystore_t *store);

/**
 * Load key store from file (simulating flash)
 * 
 * @param store Key store instance
 * @param filename File to load from
 * @return Error code
 */
error_code_t keystore_load_from_file(keystore_t *store, const char *filename);

/**
 * Save key store to file (simulating flash write)
 * 
 * @param store Key store instance
 * @param filename File to save to
 * @return Error code
 */
error_code_t keystore_save_to_file(const keystore_t *store, const char *filename);

/**
 * Add entry to key store
 * 
 * @param store Key store instance
 * @param id Entry ID
 * @param type Entry type
 * @param data Entry data
 * @param size Data size
 * @return Error code
 */
error_code_t keystore_add_entry(keystore_t *store, uint32_t id, keystore_entry_type_t type, const uint8_t *data, size_t size);

/**
 * Get entry from key store
 * 
 * @param store Key store instance
 * @param id Entry ID
 * @param data Output buffer for data
 * @param size Buffer size (in), actual size (out)
 * @param type Entry type (output, optional)
 * @return Error code
 */
error_code_t keystore_get_entry(const keystore_t *store, uint32_t id, uint8_t *data, size_t *size, keystore_entry_type_t *type);

/**
 * Delete entry from key store
 * 
 * @param store Key store instance
 * @param id Entry ID
 * @return Error code
 */
error_code_t keystore_delete_entry(keystore_t *store, uint32_t id);

/**
 * List all entries in key store
 * 
 * @param store Key store instance
 * @param ids Array to store entry IDs
 * @param max_ids Maximum IDs to return
 * @param num_ids Actual number of IDs returned
 * @return Error code
 */
error_code_t keystore_list_entries(const keystore_t *store, uint32_t *ids, size_t max_ids, size_t *num_ids);

/**
 * Clear all entries (secure wipe)
 * 
 * @param store Key store instance
 * @return Error code
 */
error_code_t keystore_clear(keystore_t *store);

/**
 * Verify key store integrity
 * 
 * @param store Key store instance
 * @return Error code
 */
error_code_t keystore_verify_integrity(const keystore_t *store);

/**
 * Load PEM file into memory (helper function)
 * 
 * @param filename PEM file path
 * @param buffer Output buffer
 * @param size Buffer size (in), actual size (out)
 * @return Error code
 */
error_code_t keystore_load_pem_file(const char *filename, uint8_t *buffer, size_t *size);

#endif /* SRC_KEY_STORE_H */