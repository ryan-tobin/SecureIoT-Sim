#ifndef SRC_TLS_CLIENT_H
#define SRC_TLS_CLIENT_H

/**
 * tls_client.h - TLS client interface
 * 
 * Handles TLS connection establishment, certificate validation, 
 * and secure communication using mbedTLS
 * 
 * Author: Ryan Tobin
 * Date: 2025
 */

 #include <stdint.h>
 #include <stddef.h>
 #include "error.h"
 #include "config.h"

 /* Forward decleration */
 typedef struct tls_context tls_context_t;

 /* TLS connections params */
typedef struct {
    const char *server_name;        /* Server hostname */
    uint16_t server_port;           /* Server port */
    const uint8_t *ca_cert;         /* CA certificate (DER or PEM) */
    size_t ca_cert_len;             /* CA certificate length */
    const uint8_t *client_cert;     /* Client certificate */
    size_t client_cert_len;         /* Client certificate length */
    const uint8_t *client_key;      /* Client private key */
    size_t client_key_len;          /* Client key length */
    int verify_mode;                /* Certificate verification mode */
    uint32_t timeout_ms;            /* Connection timeout in milliseconds */
} tls_config_t;

/* Certificate verification modes */
enum {
    TLS_VERIFY_NONE = 0,            /* No verification */
    TLS_VERIFY_OPTIONAL = 1,        /* Verify if cert provided */
    TLS_VERIFY_REQUIRED = 2         /* Require valid cert */
};

/**
 * Initialize TLS client context
 * 
 * @param ctx Pointer to context pointer 
 * @return Error code
 */
error_code_t tls_client_init(tls_context_t **ctx);

/**
 * Configure TLS client 
 * 
 * @param ctx TLS context
 * @param config Configuration params
 * @return Error code
 */
error_code_t tls_client_configure(tls_context_t *ctx, const tls_config_t *config);

/**
 * Connect to TLS server
 * 
 * @param ctx TLS context
 * @return Error code
 */
error_code_t tls_client_connect(tls_context_t *ctx);

/**
 * Send data over TLS connection
 * 
 * @param ctx TLS context
 * @param data Data to send
 * @param len Data length
 * @param sent Bytes actually sent
 * @return Error code
 */
error_code_t tls_client_send(tls_context_t *ctx, const uint8_t *data, size_t len, size_t *sent);

/**
 * Recieve data over TLS connection
 * 
 * @param ctx TLS context
 * @param buffer Recieve buffer
 * @param max_len Maximum bytes to receive
 * @param received Bytes actually received
 * @return Error code
 */
error_code_t tls_client_recv(tls_context_t *ctx, uint8_t *buffer, size_t max_len, size_t *received);

/**
 * Get peer cert info
 * 
 * @param ctx TLS context
 * @param subject Certificate subject (output, optional)
 * @param subject_len Subject buffer length
 * @param issuer Certificate issuer (output, optional)
 * @param issuer_len Issuer buffer length
 * @return Error code
 */
error_code_t tls_client_get_peer_cert_info(tls_context_t *ctx, char *subject, size_t subject_len, char *issuer, size_t issuer_len);

/**
 * Close TLS connection
 * 
 * @param ctx TLS context
 * @return Error code
 */
error_code_t tls_client_close(tls_context_t *ctx);

/**
 * Destroy TLS client context
 * 
 * @param ctx TLS context
 */
void tls_client_destroy(tls_context_t *ctx);

#endif /* SRC_TLS_CLIENT_H */

                        