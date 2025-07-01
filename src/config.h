#ifndef SRC_CONFIG_H
#define SRC_CONFIG_H

/**
 * config.h - SecureIoT-Sim configuration constants
 * 
 * Global configuration parameters for the simulator
 * 
 * Author: Ryan Tobin
 * Date: 2025
 */

/* Version information */
#define VERSION_MAJOR 1
#define VERSION_MINOR 0
#define VERSION_PATCH 0

/* Buffer sizes - fixed to avoid dynamic allocation */
#define MAX_CERT_SIZE       4096    /* Maximum certificate size in bytes */
#define MAX_KEY_SIZE        4096    /* Maximum private key size in bytes */
#define MAX_MSG_SIZE        1024    /* Maximum message size */
#define MAX_HOSTNAME_LEN    256     /* Maximum hostname length */
#define MAX_PATH_LEN        512     /* Maximum file path length */

/* TLS configuration */
#define TLS_HANDSHAKE_TIMEOUT   30  /* Handshake timeout in seconds */
#define TLS_READ_TIMEOUT        10  /* Read timeout in seconds */
#define TLS_WRITE_TIMEOUT       10  /* Write timeout in seconds */
#define TLS_MIN_VERSION         0x0303  /* TLS 1.2 */
#define TLS_MAX_VERSION         0x0304  /* TLS 1.3 */

/* Network configuration */
#define DEFAULT_SERVER_HOST     "localhost"
#define DEFAULT_SERVER_PORT     8443
#define SOCKET_BUFFER_SIZE      4096

/* Key store configuration */
#define KEYSTORE_MAX_ENTRIES    10  /* Maximum number of stored certs/keys */
#define KEYSTORE_MAGIC          0x4B455953  /* "KEYS" in hex */

/* Message protocol */
#define MSG_PROTOCOL_VERSION    1

/* Debugging */
#ifdef DEBUG
    #define DEBUG_PRINT(fmt, ...) \
        fprintf(stderr, "[DEBUG] %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#else
    #define DEBUG_PRINT(fmt, ...) ((void)0)
#endif

/* Static assertions for compile-time checks */
#define STATIC_ASSERT(cond, msg) typedef char static_assertion_##msg[(cond)?1:-1]

/* Ensure reasonable buffer sizes */
STATIC_ASSERT(MAX_CERT_SIZE >= 1024, cert_buffer_too_small);
STATIC_ASSERT(MAX_MSG_SIZE >= 256, msg_buffer_too_small);

#endif /* SRC_CONFIG_H */