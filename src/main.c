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

    /* TODO: Initialize key store */
    /* TODO: Load certificates and keys */
    /* TODO: Initialize TLS client */
    /* TODO: Connect to server */
    /* TODO: Send telemetry message */
    /* TODO: Receive response */
    /* TODO: Clean up */

    return ret;
}