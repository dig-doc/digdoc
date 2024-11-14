#include <stdio.h>
#include <coap3/coap.h>

#define TU_SERVER_IP "141.30.1.1"
#define COAP_PROXY_HOST "127.0.0.1"
#define COAP_PROXY_PORT 12345

coap_context_t *create_coap_context() {
    coap_context_t *ctx = coap_new_context(NULL);
    if (!ctx) {
        fprintf(stderr, "Failed to create CoAP context\n");
        return NULL;
    }
    return ctx;
}

coap_session_t *create_coap_session(coap_context_t *ctx) {
    coap_address_t proxy_addr;
    coap_address_init(&proxy_addr);

    // Set the proxy IP address and port for CoAP
    proxy_addr.addr.sin.sin_family = AF_INET;
    proxy_addr.addr.sin.sin_port = htons(COAP_PROXY_PORT);
    if (inet_pton(AF_INET, COAP_PROXY_HOST, &proxy_addr.addr.sin.sin_addr) <= 0) {
        fprintf(stderr, "Invalid proxy IP address: %s\n", COAP_PROXY_HOST);
        coap_free_context(ctx);
        return NULL;
    }

    // Create the CoAP session with the specified proxy address
    coap_session_t *session = coap_new_client_session(ctx, NULL, &proxy_addr, COAP_PROTO_UDP);
    if (!session) {
        fprintf(stderr, "Failed to create CoAP session\n");
        coap_free_context(ctx);
        return NULL;
    }

    return session;
}

void handle_coap_response(coap_context_t *ctx, coap_session_t *session, coap_pdu_t *response) {
    size_t len;
    const uint8_t *data;

    // Check if the response has data
    if (coap_get_data(response, &len, &data)) {
        printf("Received CoAP response:\n");
        fwrite(data, 1, len, stdout);  // Print the raw response data
        printf("\n");
    } else {
        printf("No data received in response\n");
    }
}


int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <hostname>\n", argv[0]);
        return EXIT_FAILURE;
    }

    coap_startup();

    // Create CoAP context
    coap_context_t *ctx = create_coap_context();
    if (!ctx) return EXIT_FAILURE;

    // Create CoAP session to proxy
    coap_session_t *session = create_coap_session(ctx);
    if (!session) {
        coap_free_context(ctx);
        return EXIT_FAILURE;
    }

    // Register the response handler
    coap_register_response_handler(ctx, handle_coap_response);

    // Send the DNS request over CoAP
//    send_coap_dns_request(session, argv[1]);

    // Event loop to wait for and process CoAP responses
    printf("start waiting\n");
    while (1) {
        coap_io_process(ctx, COAP_IO_WAIT);  // Wait for events and process them
    }
    printf("end waiting\n");

    // Clean up resources
    coap_session_release(session);
    coap_free_context(ctx);
    coap_cleanup();
    return EXIT_SUCCESS;
}



