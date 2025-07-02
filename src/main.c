/**
 * main.c - SecureIoT-Sim entry point
 * 
 * Main program that demonstrates secure IoT device communication
 * using TLS/mTLS with X.509 certificates
 * 
 * Author: Ryan Tobin
 * Date: 2025
 */

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <signal.h>
 #include <unistd.h>

 #include "config.h"
 #include "error.h"
 #include "tls_client.h"
 #include "key_store.h"
 #include "msg_protocol.h"

 /* Global state for signal handling */
 static volatile int g_shutdown = 0;

 /**
  * Signal handler for graceful shutdown
  * 
  * @param sig Signal number
  */
 static void signal_handler(int sig)
 {
    (void)sig;
    g_shutdown = 1;
 }

/**
 * Load certificates and keys from files
 * 
 * @param cert_file Certificate file path
 * @param key_file Private key file path
 * @param ca_file CA certificate file path
 * @param config TLS configuration to populate
 * @return Error code
 */
static error_code_t load_certificates(const char *cert_file, const char *key_file, const char *ca_file, tls_config_t *config)
{
    static uint8_t cert_buffer[MAX_CERT_SIZE];
    static uint8_t key_buffer[MAX_KEY_SIZE];
    static uint8_t ca_buffer[MAX_CERT_SIZE];
    size_t cert_size = sizeof(cert_buffer);
    size_t key_size = sizeof(key_buffer);
    size_t ca_size = sizeof(ca_buffer);
    error_code_t ret;

    /* Load device certificate */
    ret = keystore_load_pem_file(cert_file, cert_buffer, &cert_size);
    if (ret != ERR_OK) {
        fprintf(stderr, "Failed to load certificate: %s\n", error_to_string(ret));
        return ret;
    }
    config->client_cert = cert_buffer;
    config->client_cert_len = cert_size;

    /* load priv key */
    ret = keystore_load_pem_file(key_file, key_buffer, &key_size);
    if (ret != ERR_OK) {
        fprintf(stderr, "Failed to load private key: %s\n", error_to_string(ret));
        return ret;
    }
    config->client_key = key_buffer;
    config->client_key_len = key_size;

    /* load CA certificate */
    ret = keystore_load_pem_file(ca_file, ca_buffer, &ca_size);
    if (ret != ERR_OK) {
        fprintf(stderr, "Failed to load CA certificate: %s\n", error_to_string(ret));
        return ret;
    }
    config->ca_cert = ca_buffer;
    config->ca_cert_len = ca_size;

    return ERR_OK;
}

/**
 * Create sample telemetry data
 * 
 * @param telemetry Telemetry structure to fill
 */
static void create_telemetry_data(telemetry_data_t *telemetry)
{
    static uint32_t uptime = 0;

    telemetry->timestamp = msg_get_timestamp();
    telemetry->temperature = 22.5f + ((rand() % 100) - 50) / 10.0f;
    telemetry->humidity = 65.0f + ((rand() % 200) - 100) / 10.0f;
    telemetry->pressure = 1013.25f + ((rand() % 100) - 50) / 10.0f;
    telemetry->battery_mv = 3000 + (rand() % 600);
    telemetry->uptime_sec = uptime++;
}

 /**
  * Print usage information
  * 
  * @param prog_name Program name
  */
static void print_usage(const char *prog_name)
{
    printf("Usage: %s [options]\n", prog_name);
    printf("Options:\n");
    printf("  -h, --help          Show this help message\n");
    printf("  -s, --server HOST   Server hostname (default: localhost)\n");
    printf("  -p, --port PORT     Server port (default: 8443)\n");
    printf("  -c, --cert FILE     Device certificate file\n");
    printf("  -k, --key FILE      Device private key file\n");
    printf("  -a, --ca FILE       CA certificate file\n");
    printf("  -v, --verbose       Enable verbose output\n");
}

/**
 * Main entry point 
 * 
 * @param argc Argument count
 * @param argv Argument vector
 * @return Exit status
 */
int main(int argc, char *argv[])
{
    int ret = 0;
    const char *server = "localhost";
    int port = 8443;
    const char *cert_file = "certs/device_cert.pem";
    const char *key_file = "certs/device_key.pem";
    const char *ca_file = "certs/ca_cert.pem";
    int verbose = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        else if ((strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--server") == 0) && i + 1 < argc) {
            server = argv[++i];
        }
        else if ((strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0) && i + 1 < argc) {
            port = atoi(argv[++i]);
        }
        else if ((strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--cert") == 0) && i + 1 < argc) {
            cert_file = argv[++i];
        }
        else if ((strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--key") == 0) && i + 1 < argc) {
            key_file = argv[++i];
        }
        else if ((strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--ca") == 0) && i + 1 < argc) {
            ca_file = argv[++i];
        }
        else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
        }
        else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("SecureIoT-Sim: Ready\n");
    printf("Version: %d.%d.%d\n", VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH);

    if (verbose) {
        printf("Configuration:\n");
        printf("  Server: %s:%d\n", server, port);
        printf("  Device cert: %s\n", cert_file);
        printf("  Device key: %s\n", key_file);
        printf("  CA cert: %s\n", ca_file);
    }

    /* Initialize TLS client */
    tls_context_t *tls_ctx = NULL;
    ret = tls_client_init(&tls_ctx);
    if (ret != ERR_OK) {
        fprintf(stderr, "Failed to initialize TLS client: %s\n", error_to_string(ret));
        return 1;
    }

    /* config TLS */
    tls_config_t tls_config = {
        .server_name = server,
        .server_port = (uint16_t)port,
        .verify_mode = TLS_VERIFY_REQUIRED,
        .timeout_ms = 30000
    };

    /* load certificates */
    ret = load_certificates(cert_file, key_file, ca_file, &tls_config);
    if (ret != ERR_OK) {
        tls_client_destroy(tls_ctx);
        return 1;
    }

    ret = tls_client_configure(tls_ctx, &tls_config);
    if (ret != ERR_OK) {
        fprintf(stderr, "Failed to configure TLS: %s\n", error_to_string(ret));
        tls_client_destroy(tls_ctx);
        return 1;
    }

    /* Connect to server */
    fprintf("Connecting to %s:%d...\n", server, port);
    ret = tls_client_connect(tls_ctx);
    if (ret != ERR_OK) {
        fprintf(stderr, "Failed to connect: %s\n", error_to_string(ret));
        tls_client_destroy(tls_ctx);
        return 1;
    }

    printf("Connected successfully");

    /* Get peer certificate info */
    char subject[256];
    char issuer[256];
    ret = tls_client_get_peer_cert_info(tls_ctx, subject, sizeof(subject), issuer, sizeof(issuer));
    if (ret == ERR_OK) {
        printf("Server certificate:\n");
        printf("    Subject: %s\n", subject);
        printf("    Issuer: %s\n", issuer);
    }

    /* Main communication loop */
    while (!g_shutdown) {
        telemetry_data_t telemetry;
        create_telemetry_data(&telemetry);

        /* Format as json */
        char msg_buffer[MAX_MSG_SIZE];
        size_t msg_len;
        ret = msg_format_telemetry(&telemetry, msg_buffer, sizeof(msg_buffer), &msg_len);
        if (ret != ERR_OK) {
            fprintf(stderr, "Failed to format message: %s\n", error_to_string(ret));
            break;
        }

        if (verbose) {
            printf("Sending telemetry: %s\n", msg_buffer);
        }

        /* send message */
        size_t sent;
        ret = tls_client_send(tls_ctx, (uint8_t *)msg_buffer, msg_len, &sent);
        if (ret != ERR_OK) {
            fprintf(stderr, "Failed to send message: %s\n", error_to_string(ret));
            break;
        }

        /* receieve response */
        uint8_t recv_buffer[MAX_MSG_SIZE];
        size_t received = 0;

        /* wait for response with timeout */
        int timeout_count = 0;
        while (received == 0 && timeout_count < 50 && !g_shutdown) {
            ret = tls_client_recv(tls_ctx, recv_buffer, sizeof(recv_buffer) - 1, &received);
            if (ret != ERR_OK) {
                fprintf(stderr, "Failed to receive response: $s\n", error_to_string(ret));
                break;
            }

            if (received == 0) {
                usleep(100000);
                timeout_count++;
            }
        }

        if (received > 0) {
            recv_buffer[received] = '\0';

            if (verbose) {
                printf("Received response: %s\n", (char *)recv_buffer);
            }

            /* parse response */
            message_t response_msg;
            ret = msg_parse_json((char *)recv_buffer, received, &response_msg);
            if (ret == ERR_OK && response_msg.type == MSG_TYPE_RESPONSE) {
                printf("Server acknowledged: %s\n", response_msg.data.response.message);
            }
        }

        /* wait before next telemetry */
        for (int i = 0; i < 50 && !g_shutdown; i++) {
            usleep(100000);
        }
    }

    /* cleanup */
    printf("\nShutting down...\n");
    tls_client_close(tls_ctx);
    tls_client_destroy(tls_ctx);

    return 0;
}