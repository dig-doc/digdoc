#include <stdio.h>
#include <string.h>
#include <coap3/coap.h>
#include <netdb.h>

#define TU_SERVER_IP "141.30.1.1"
#define COAP_PROXY_HOST "127.0.0.1"
#define COAP_PROXY_PORT "5683"

int resolve_address(const char *host, const char *service, coap_address_t *dst);
coap_response_t handle_response(coap_session_t *coapSession, const coap_pdu_t *sentPdu, const coap_pdu_t *receivedPdu, const coap_mid_t messageId) {
    coap_show_pdu(LOG_INFO, receivedPdu);

    int* ackReceived = (int*) coap_session_get_app_data(coapSession);
    *ackReceived = 1;

    return COAP_RESPONSE_OK;
}
// from https://github.com/obgm/libcoap-minimal/blob/main/common.cc
int resolve_address(const char *host, const char *service, coap_address_t *dst) {

    struct addrinfo *res, *ainfo;
    struct addrinfo hints;
    int error, len=-1;

    memset(&hints, 0, sizeof(hints));
    memset(dst, 0, sizeof(*dst));
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_family = AF_UNSPEC;

    error = getaddrinfo(host, service, &hints, &res);

    if (error != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error));
        return error;
    }

    for (ainfo = res; ainfo != NULL; ainfo = ainfo->ai_next) {
        switch (ainfo->ai_family) {
            case AF_INET6:
            case AF_INET:
                len = dst->size = ainfo->ai_addrlen;
                memcpy(&dst->addr.sin6, ainfo->ai_addr, dst->size);
                goto finish;
            default:
                ;
        }
    }

    finish:
    freeaddrinfo(res);
    return len;
}

int main(int argc, char const *argv[]) {
    int errorCode;
    int returnCode = 0;
    coap_context_t* coapContext = NULL;
    int ackReceived;
    coap_address_t serverAddress;
    coap_session_t* coapSession = NULL;
    coap_pdu_t* pdu;

    coap_startup();
    coap_set_log_level(LOG_DEBUG);

    errorCode = resolve_address(COAP_PROXY_HOST, COAP_PROXY_PORT, &serverAddress);
    if (errorCode < 0) {
        printf("Could not resolve remote address!\n");
        returnCode = 1;
        goto cleanup;
    }

    coapContext = coap_new_context(NULL);
    if (!coapContext) {
        printf("Could not create CoAP context!\n");
        returnCode = 1;
        goto cleanup;
    }

    coap_register_response_handler(coapContext, handle_response);

    coapSession = coap_new_client_session(coapContext, NULL, &serverAddress, COAP_PROTO_UDP);
    if (!coapSession) {
        printf("Could not create CoAP session!\n");

        returnCode = 1;
        goto cleanup;
    }

    coap_session_set_app_data(coapSession, &ackReceived);

    pdu = coap_pdu_init(
            COAP_MESSAGE_CON,
            COAP_REQUEST_CODE_GET,
            coap_new_message_id(coapSession),
            coap_session_max_pdu_size(coapSession)
            );
    if (!pdu) {
        printf("Could not create CoAP PDU!\n");
        returnCode = 1;
        goto cleanup;
    }

    uint8_t messageToken[8];
    size_t tokenLength;
    coap_session_new_token(coapSession, &tokenLength, messageToken);
    coap_add_token(pdu, tokenLength, messageToken);

char server_uri[50];
    snprintf(server_uri, sizeof(server_uri), "coap://%s/", COAP_PROXY_HOST);
    coap_uri_t uri;
    coap_split_uri(server_uri, strlen(server_uri), &uri);
    coap_add_option(pdu, COAP_OPTION_URI_PATH, uri.path.length, uri.path.s);

    ackReceived = 0;
    coap_send(coapSession, pdu);
    while (!ackReceived) {
        coap_io_process(coapContext, COAP_IO_WAIT);
    }

    cleanup:
    if (coapSession != NULL) {
        coap_session_release(coapSession);
    }
    if (coapContext != NULL) {
        coap_free_context(coapContext);
    }
    coap_cleanup();

    return returnCode;
}