#include <stdio.h>
#include <string.h>
#include <coap3/coap.h>

#include "main.h"
#include "coap_helper.h"


coap_response_t handle_response(coap_session_t *coapSession, const coap_pdu_t *sentPdu, const coap_pdu_t *receivedPdu,  const coap_mid_t messageId) {

    size_t data_len;
    const uint8_t *data;

    if (!coap_get_data(receivedPdu, &data_len, &data)) {
        printf("Failed to get data from response.\n");
        return COAP_RESPONSE_FAIL;
    }

    if (data_len <= 0) {
        printf("No data in response.\n");
        return COAP_RESPONSE_FAIL;
    }

    // parse dns response
    parse_dns_response(data, data_len);
    int *ackReceived = (int *) coap_session_get_app_data(coapSession);
    *ackReceived = 1;

    return COAP_RESPONSE_OK;
}




int main(int argc, char const *argv[]) {

    int errorCode;
    int returnCode = 0;
    coap_context_t *coapContext = NULL;
    int ackReceived;
    coap_address_t serverAddress;
    coap_session_t *coapSession = NULL;
    coap_pdu_t *pdu;

    coap_startup();
   // coap_set_log_level(LOG_DEBUG);

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

    // create session
    coapSession = coap_new_client_session(coapContext, NULL, &serverAddress, COAP_PROTO_UDP);
    if (!coapSession) {
        printf("Could not create CoAP session!\n");
        returnCode = 1;
        goto cleanup;
    }
    coap_session_set_app_data(coapSession, &ackReceived);

    // create pdu
    pdu = coap_pdu_init(
            COAP_MESSAGE_CON,
            COAP_REQUEST_CODE_POST,
            coap_new_message_id(coapSession),
            coap_session_max_pdu_size(coapSession)
    );
    if (!pdu) {
        printf("Could not create CoAP PDU!\n");
        returnCode = 1;
        goto cleanup;
    }

    // create session
    uint8_t messageToken[8];
    size_t tokenLength;
    coap_session_new_token(coapSession, &tokenLength, messageToken);
    coap_add_token(pdu, tokenLength, messageToken);

    // add coap uri
    char server_uri[50];
    snprintf(server_uri, sizeof(server_uri), COAP_FORMAT, COAP_PROXY_HOST);
    coap_uri_t uri;
    coap_split_uri(server_uri, strlen(server_uri), &uri);
    coap_add_option(pdu, COAP_OPTION_URI_PATH, uri.path.length, uri.path.s);

    // add headers: https://datatracker.ietf.org/doc/html/draft-ietf-core-dns-over-coap#name-new-application-dns-message
    uint8_t accept_option_buffer[2];
    size_t accept_option_length = coap_encode_var_safe(accept_option_buffer, sizeof(accept_option_buffer), 553);
    coap_add_option(pdu, COAP_OPTION_ACCEPT, accept_option_length, accept_option_buffer);
    uint8_t content_format_buffer[2];
    size_t content_format_length = coap_encode_var_safe(content_format_buffer, sizeof(content_format_buffer), 553);
    coap_add_option(pdu, COAP_OPTION_CONTENT_FORMAT, content_format_length, content_format_buffer);

    // query
    uint8_t dns_query[512];
    size_t query_len = build_dns_query("google.de", dns_query);
    coap_add_data(pdu, query_len, dns_query);

    // send
    ackReceived = 0;
    coap_send(coapSession, pdu);

    // wait for ACK and handle response
    while (!ackReceived) {
        coap_io_process(coapContext, COAP_IO_WAIT);
    }

    // cleanup
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