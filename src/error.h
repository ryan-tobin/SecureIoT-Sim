#ifndef SRC_ERROR_H
#define SRC_ERROR_H

/**
 * error.h - Error codes and handling
 * 
 * Centralized error code defintions for SecuireIoT-Sim
 * 
 * Author: Ryan Tobin
 * Date: 2025
 */

 /* Error code enumeration */
typedef enum {
    ERR_OK                  = 0,    /* Success */
    ERR_INVALID_PARAM       = -1,   /* Invalid parameter */
    ERR_OUT_OF_MEMORY       = -2,   /* Memory allocation failed */
    ERR_BUFFER_TOO_SMALL    = -3,   /* Buffer too small */
    ERR_FILE_NOT_FOUND      = -4,   /* File not found */
    ERR_FILE_READ           = -5,   /* File read error */
    ERR_FILE_WRITE          = -6,   /* File write error */
    ERR_TLS_INIT            = -10,  /* TLS initialization failed */
    ERR_TLS_CONNECT         = -11,  /* TLS connection failed */
    ERR_TLS_HANDSHAKE       = -12,  /* TLS handshake failed */
    ERR_TLS_CERT_VERIFY     = -13,  /* Certificate verification failed */
    ERR_TLS_WRITE           = -14,  /* TLS write failed */
    ERR_TLS_READ            = -15,  /* TLS read failed */
    ERR_CERT_INVALID        = -20,  /* Invalid certificate */
    ERR_KEY_INVALID         = -21,  /* Invalid private key */
    ERR_CERT_EXPIRED        = -22,  /* Certificate expired */
    ERR_CERT_NOT_YET_VALID  = -23,  /* Certificate not yet valid */
    ERR_KEYSTORE_FULL       = -30,  /* Key store full */
    ERR_KEYSTORE_NOT_FOUND  = -31,  /* Entry not found in key store */
    ERR_MSG_INVALID_FORMAT  = -40,  /* Invalid message format */
    ERR_MSG_TOO_LARGE       = -41,  /* Message too large */
    ERR_NETWORK             = -50,  /* Network error */
    ERR_TIMEOUT             = -51,  /* Operation timeout */
    ERR_NOT_IMPLEMENTED     = -99,  /* Feature not implemented */
    ERR_UNKNOWN             = -100  /* Unknown error */
} error_code_t;

/**
 * Get human readable error string
 * 
 * @param err Error code 
 * @return Error description string 
 */
static inline const char* error_to_string(error_code_t err)
{
    switch (err) {
        case ERR_OK:                    return "Success";
        case ERR_INVALID_PARAM:         return "Invalid parameter";
        case ERR_OUT_OF_MEMORY:         return "Out of memory";
        case ERR_BUFFER_TOO_SMALL:      return "Buffer too small";
        case ERR_FILE_NOT_FOUND:        return "File not found";
        case ERR_FILE_READ:             return "File read error";
        case ERR_FILE_WRITE:            return "File write error";
        case ERR_TLS_INIT:              return "TLS initialization failed";
        case ERR_TLS_CONNECT:           return "TLS connection failed";
        case ERR_TLS_HANDSHAKE:         return "TLS handshake failed";
        case ERR_TLS_CERT_VERIFY:       return "Certificate verification failed";
        case ERR_TLS_WRITE:             return "TLS write failed";
        case ERR_TLS_READ:              return "TLS read failed";
        case ERR_CERT_INVALID:          return "Invalid certificate";
        case ERR_KEY_INVALID:           return "Invalid private key";
        case ERR_CERT_EXPIRED:          return "Certificate expired";
        case ERR_CERT_NOT_YET_VALID:    return "Certificate not yet valid";
        case ERR_KEYSTORE_FULL:         return "Key store full";
        case ERR_KEYSTORE_NOT_FOUND:    return "Entry not found in key store";
        case ERR_MSG_INVALID_FORMAT:    return "Invalid message format";
        case ERR_MSG_TOO_LARGE:         return "Message too large";
        case ERR_NETWORK:               return "Network error";
        case ERR_TIMEOUT:               return "Operation timeout";
        case ERR_NOT_IMPLEMENTED:       return "Feature not implemented";
        case ERR_UNKNOWN:               return "Unknown error";
        default:                        return "Undefined error";
    }
}

/* Error checking macros */
#define CHECK_PARAM(param) \
    do { \
        if ((param) == NULL) { \
            return ERR_INVALID_PARAM; \
        } \
    } while (0)

#define CHECK_ERROR(expr) \
    do { \
        error_code_t _err = (expr); \
        if (_err != ERR_OK) { \
            return _err; \
        } \
    } while (0)

#define CHECK_ERROR_GOTO(expr, label) \
    do { \
        error_code_t _err = (expr); \
        if (_err != ERR_OK) { \
            ret = _err; \
            goto label; \
        } \
    } while (0)

#endif /* SRC_ERROR_H */