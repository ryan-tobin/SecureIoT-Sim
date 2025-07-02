/**
 * tls_client.c - TLS client implementation
 * 
 * Handles TLS connection establishment, certificate validation,
 * and secure communication using mbedTLS
 * 
 * Author: Ryan Tobin
 * Date: 2025
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tls_client.h"
#include "config.h"
#include "error.h"

#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509.h"
#include "mbedtls/pk.h"
#include "mbedtls/debug.h"

/* TLS context structure */
struct tls_context {
    /* mbedTLS contexts */
    mbedtls_net_context server_fd;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
    mbedtls_x509_crt clicert;
    mbedtls_pk_context pkey;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    /* Connection info */
    char hostname[MAX_HOSTNAME_LEN];
    uint16_t port;

    /* State */
    int initialized;
    int connected;
};

/**
 * Debug callback for mbedTLS
 */
static void tls_debug_callback(void *ctx, int level, const char *file, int line, const char *str)
{
    (void)ctx;
    (void)level;
    DEBUG_PRINT("[mbedTLS] %s:%d: %s", file, line, str);
}

/**
 * Initialize TLS client context
 */
error_code_t tls_client_init(tls_context_t **ctx)
{
    CHECK_PARAM(ctx);
    
    tls_context_t *new_ctx = calloc(1, sizeof(tls_context_t));
    if (new_ctx == NULL) {
        return ERR_OUT_OF_MEMORY;
    }

    /* Initalize mbedTLS structures */
    mbedtls_net_init(&new_ctx->server_fd);
    mbedtls_ssl_init(&new_ctx->ssl);
    mbedtls_ssl_config_init(&new_ctx->conf);
    mbedtls_x509_crt_init(&new_ctx->cacert);
    mbedtls_x509_crt_init(&new_ctx->clicert);
    mbedtls_pk_init(&new_ctx->pkey);
    mbedtls_ctr_drbg_init(&new_ctx->ctr_drbg);
    mbedtls_entropy_init(&new_ctx->entropy);

    /* Seed RNG */
    const char *pers = "secureiot_sim_client";
    int ret = mbedtls_ctr_drbg_seed(&new_ctx->ctr_drbg, mbedtls_entropy_func, &new_ctx->entropy,(const unsigned char *)pers, strlen(pers));

    if (ret != 0) {
        DEBUG_PRINT("mbedtls_ctr_drbg_seed failed: -0x%04x", -ret);
        free(new_ctx);
        return ERR_TLS_INIT;
    }

    new_ctx->initialized = 1;
    *ctx = new_ctx;
    
    return ERR_OK;
}

/**
 * Configure TLS client
 */
error_code_t tls_client_configure(tls_context_t *ctx, const tls_config_t *config)
{
    CHECK_PARAM(ctx);
    CHECK_PARAM(config);
    
    if (!ctx->initialized) {
        return ERR_TLS_INIT;
    }    

    int ret;

    strncpy(ctx->hostname, config->server_name, MAX_HOSTNAME_LEN - 1);
    ctx->hostname[MAX_HOSTNAME_LEN -1] = '\0' ;
    ctx->port = config->server_port;

    /* Load CA certificate */
    if (config->ca_cert != NULL && config->ca_cert_len > 0) {
        ret = mbedtls_x509_crt_parse(&ctx->cacert, config->ca_cert, config->ca_cert_len);
        
        if (ret != 0) {
            DEBUG_PRINT("mbedtls_x509_crt_parse (CA) failed: -0x%04x", -ret);
            return ERR_CERT_INVALID;
        }
    }

    /* Load client certificate */
    if (config->client_cert != NULL && config->client_cert_len > 0) {
        ret = mbedtls_x509_crt_parse(&ctx->clicert, config->client_cert, config->client_cert_len);

        if (ret != 0) {
            DEBUG_PRINT("mbedtls_x509_crt_parse (client) failed: -0x%04x", -ret);
            return ERR_CERT_INVALID;
        }
    }

    /* Load client priv key */
    if (config->client_key != NULL && config->client_key_len > 0) {
        ret = mbedtls_pk_parse_key(&ctx->pkey, config->client_key, config->client_key_len, NULL, 0);

        if (ret != 0) {
            DEBUG_PRINT("mbedtls_pk_parse_key failed: -0x%04x", -ret);
            return ERR_KEY_INVALID;
        }
    }

    /* Config SSL */
    ret = mbedtls_ssl_config_defaults(&ctx->conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);

    if (ret != 0){
        DEBUG_PRINT("mbedtls_ssl_config_defaults failed: -0x%04x", -ret);
        return ERR_TLS_INIT;
    }

    /* Set verification mode */
    if (config->verify_mode == TLS_VERIFY_REQUIRED) {
        mbedtls_ssl_conf_authmode(&ctx->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    } else if (config-> verify_mode == TLS_VERIFY_OPTIONAL) {
        mbedtls_ssl_conf_authmode(&ctx->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    } else {
        mbedtls_ssl_conf_authmode(&ctx->conf, MBEDTLS_SSL_VERIFY_NONE);
    }

    mebdtls_ssl_conf_ca_chain(&ctx->conf, &ctx->cacert, NULL);
    mbedtls_ssl_conf_rng(&ctx->conf, mbedtls_ctr_drbg_random, &ctx->ctr_drbg);

    /* Set client certificate if provided */
    if (config->client_cert != NULL) {
        ret = mbedtls_ssl_conf_own_cert(&ctx->conf, &ctx->clicert, &ctx->pkey);
        if (ret != 0) {
            DEBUG_PRINT("mbedtls_ssl_conf_own_cert failed: -0x%04x", -ret);
            return ERR_TLS_INIT;
        }
    }

    /* Enable debug output */
    #ifdef DEBUG
    mbedtls_ssl_conf_dbg(&ctx->conf, tls_debug_callback, NULL);
    mbedtls_debug_set_threshold(2);
    #endif

    /* Setup SSL context */
    ret = mbedtls_ssl_setup(&ctx->ssl, &ctx->conf);;
    if (ret != 0) {
        DEBUG_PRINT("mbedtls_ssl_setup failed: -0x%04x", -ret);
        return ERR_TLS_INIT;
    }

    /* Set hostname for SNI */
    ret = mbedtls_ssl_set_hostname(&ctx->ssl, ctx->hostname);
    if (ret != 0) {
        DEBUG_PRINT("mbedtls_ssl_set_hostname failed: -0x%04x", -ret);
        return ERR_TLS_INIT;
    }

    return ERR_OK;
}

/**
 * Connect to TLS server
 */
error_code_t tls_client_connect(tls_context_t *ctx)
{
    CHECK_PARAM(ctx);
    
    if (!ctx->initialized) {
        return ERR_TLS_INIT;
    }

    if (ctx->connected) {
        return ERR_OK;
    }

    int ret;
    char port_str[16];

    snprintf(port_str, sizeof(port_str), "%u", ctx->port);

    /* Start connection */
    ret = mbedtls_net_connect(&ctx->server_fd, ctx->hostname, port_str, MBEDTLS_NET_PROTO_TCP);

    if (ret != 0) {
        DEBUG_PRINT("mbedtls_net_connect failed: -0x%04x", -ret);
        return ERR_TLS_CONNECT;
    }

    /* Set socket to non-blocking for timeouts */
    mbedtls_net_set_nonblock(&ctx->server_fd);

    /* Set BIO callbacks */
    mbedtls_ssl_set_bio(&ctx->ssl, &ctx->server_fd, mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout);

    /* SSL handshake */
    DEBUG_PRINT("Performing TLS handshake...");
    while ((ret = mbedtls_ssl_handshake(&ctx->ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            DEBUG_PRINT("mbedtls_ssl_handshake failed: -0x%04x", -ret);
            mbedtls_net_free(&ctx->server_fd);

            if (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
                return ERR_TLS_CERT_VERIFY;
            }
            return ERR_TLS_HANDSHAKE;
        }
    }

    DEBUG_PRINT("TLS handshake successful");

    /* verify server certificate */
    uint32_t flags = mbedtls_ssl_get_verify_result(&ctx->ssl);
    if (flags != 0) {
        char vrfy_buf[512];
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), " ! ", flags);
        DEBUG_PRINT("Certificate verification failed:\n%s", vrfy_buf);

        if ((flags & MBEDTLS_X509_BADCERT_EXPIRED) != 0) {
            return ERR_CERT_EXPIRED;
        }
        if ((flags & MBEDTLS_X509_BADCERT_NOT_TRUSTED) != 0) {
            return ERR_TLS_CERT_VERIFY;
        }
        return ERR_TLS_CERT_VERIFY;
    }

    ctx->connected = 1;
    DEBUG_PRINT("Connected successfully with %s", mbedtls_ssl_get_ciphersuite(&ctx->ssl));
    
    return ERR_OK;
}

/**
 * Send data over TLS connection
 */
error_code_t tls_client_send(tls_context_t *ctx, const uint8_t *data, 
                             size_t len, size_t *sent)
{
    CHECK_PARAM(ctx);
    CHECK_PARAM(data);
    CHECK_PARAM(sent);
    
    if (!ctx->connected) {
        return ERR_TLS_CONNECT;
    }

    *sent = 0;

    while (*sent < len) {
        int ret = mbedtls_ssl_write(&ctx->ssl, data + *sent, len - *sent);

        if (ret > 0) {
            *sent += (size_t)ret;
        } else if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        } else {
            DEBUG_PRINT("mbedtls_ssl_write failed: -0x%04x", -ret);
            return ERR_TLS_WRITE;
        }
    }

    DEBUG_PRINT("Sent %zu bytes", *sent);
    return ERR_OK;
}

/**
 * Receive data over TLS connection
 */
error_code_t tls_client_recv(tls_context_t *ctx, uint8_t *buffer, 
                             size_t max_len, size_t *received)
{
    CHECK_PARAM(ctx);
    CHECK_PARAM(buffer);
    CHECK_PARAM(received);
    
    if (!ctx->connected) {
        return ERR_TLS_CONNECT;
    }

    int ret = mbedtls_ssl_read(&ctx->ssl, buffer, max_len);

    if (ret > 0) {
        *received = (size_t)ret;
        DEBUG_PRINT("Received %zu bytes", *received);
        return ERR_OK;
    } else if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
        *received = 0;
        return ERR_OK;
    } else if (ret == 0) {
        *received = 0;
        return ERR_OK;
    } else {
        DEBUG_PRINT("mbedtls_ssl_read failed: -0x%04x", -ret);
    }
}

/**
 * Get peer certificate info
 */
error_code_t tls_client_get_peer_cert_info(tls_context_t *ctx, 
                                           char *subject, size_t subject_len,
                                           char *issuer, size_t issuer_len)
{
    CHECK_PARAM(ctx);
    
    if (!ctx->connected) {
        return ERR_TLS_CONNECT;
    }

    const mbedtls_x509_crt *peer_cert = mbedtls_ssl_get_peer_cert(&ctx->ssl);
    if (peer_cert == NULL) {
        return ERR_CERT_INVALID;
    }

    /* Get subject */
    if (subject != NULL && subject_len > 0) {
        int ret = mbedtls_x509_dn_gets(subject, subject_len, &peer_cert->subject);
        if (ret < 0) {
            return ERR_BUFFER_TOO_SMALL;
        }
    }

    /* Get issuer */
    if (issuer != NULL && issuer_len > 0) {
        int ret = mbedtls_x509_dn_gets(issuer, issuer_len, &peer_cert->issuer);
        if (ret < 0) {
            return ERR_BUFFER_TOO_SMALL;
        }
    }
    
    return ERR_OK;
}

/**
 * Close TLS connection
 */
error_code_t tls_client_close(tls_context_t *ctx)
{
    CHECK_PARAM(ctx);
    
    if (!ctx->connected) {
        return ERR_OK;
    }

    /* send close notifuy */
    int ret;
    do {
        ret = mbedtls_ssl_close_notify(&ctx->ssl);
    } while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    /* close network connection */
    mbedtls_net_free(&ctx->server_fd);

    /* reset ssl session */
    mbedtls_ssl_session_reset(&ctx->ssl);

    ctx->connected = 0;
    DEBUG_PRINT("Connection closed");
    
    return ERR_OK;
}

/**
 * Destroy TLS client context
 */
void tls_client_destroy(tls_context_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    
   /* CLOSE CONNECTION IF STILL OPEN */
   if (ctx->connected) {
    tls_client_close(ctx);
   }

   mbedtls_ssl_free(&ctx->ssl);
    mbedtls_ssl_config_free(&ctx->conf);
    mbedtls_x509_crt_free(&ctx->cacert);
    mbedtls_x509_crt_free(&ctx->clicert);
    mbedtls_pk_free(&ctx->pkey);
    mbedtls_ctr_drbg_free(&ctx->ctr_drbg);
    mbedtls_entropy_free(&ctx->entropy);
    
    /* Zero and free context */
    memset(ctx, 0, sizeof(tls_context_t));
    free(ctx);
}