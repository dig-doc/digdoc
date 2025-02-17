#include <stdio.h>
#include <stdlib.h>
#include <argp.h>
#include <string.h>
#include <ldns/ldns.h>
#include <coap3/coap.h>
#include <coap3/coap_debug.h>
#include <time.h>

#define DNS_PACKET_SIZE 512U
#define DIGDOC_CF_DNS 553U

clock_t start;
bool handler_called = false;

/**
 * @brief print response
 *
 * This function prints the DNS response separated in sections.
 *
 * \param[in] pkt contains the raw DNS packet
 * \param[in] dns_length is the size of the DNS packet
 * \param[in] query_time is the time between sending a DoC packet and receiving a response in microseconds
 */

void print_output(ldns_pkt *pkt, size_t dns_length, int query_time) {
    ldns_rr_list *rr_list = ldns_pkt_question(pkt);
    if (rr_list->_rr_count > 0) {
        printf("\n;; QUESTION SECTION:\n;");
    }
    ldns_rr_list_print(stdout, rr_list);
    rr_list = ldns_pkt_answer(pkt);
    if (rr_list->_rr_count > 0) {
        printf("\n;; ANSWER SECTION:\n");
    }
    ldns_rr_list_print(stdout, rr_list);
    rr_list = ldns_pkt_authority(pkt);
    if (rr_list->_rr_count > 0) {
        printf("\n;; AUTHORITY SECTION:\n");
    }
    ldns_rr_list_print(stdout, rr_list);
    rr_list = ldns_pkt_additional(pkt);
    if (rr_list->_rr_count > 0) {
        printf("\n;; ADDITIONAL SECTION:\n");
    }
    ldns_rr_list_print(stdout, rr_list);
    printf("\n;; Query time: %dus", query_time);
    printf("\n;; DNS PKT SIZE rcvd: %ld\n", dns_length);
}

/**
 * @brief handle response
 *
 * This function is automatically called when a DoC packet was received.
 *
 * @note session, sent_pdu and message_id are not used but need to be included in the coap_response_handler_t of libcoap
 *
 * \param[in] received_pdu encapsulates the received message
 * \return COAP_RESPONSE_OK if the response is fine
 */

coap_response_t handle_response(coap_session_t *session, const coap_pdu_t *sent_pdu, const coap_pdu_t *received_pdu,
                                const coap_mid_t message_id) {
    handler_called = true;
    clock_t end = clock();

    // not used here but need to be in function arguments
    (void) session;
    (void) sent_pdu;
    (void) message_id;

    coap_show_pdu(LOG_INFO, received_pdu);

    const uint8_t *buffer;
    size_t len, off, total;
    // put the received message in a buffer -> just use the body which is "normal" DNS
    if (!coap_get_data_large(received_pdu, &len, &buffer, &off, &total)) {
        printf("No response.\n");
        return COAP_RESPONSE_OK;
    }
    // interpret 8bit int as 16bit for decoding
    const uint16_t *data = (const uint16_t *) buffer;

    ldns_buffer *ldns_buffer;
    ldns_pkt *pkt;
    ldns_buffer = ldns_buffer_new(DNS_PACKET_SIZE);
    // write data in an ldnsBuffer
    ldns_buffer_write(ldns_buffer, data, len);
    // ldnsBuffer in wire format can be converted in a DNS packet
    ldns_buffer2pkt_wire(&pkt, ldns_buffer);
    print_output(pkt, total, ((double) (end - start)) / CLOCKS_PER_SEC * 1000 * 1000);
    ldns_buffer_free(ldns_buffer);
    ldns_pkt_free(pkt);

    return COAP_RESPONSE_OK;
}

// Define a structure to hold our arguments
struct arguments {
    char *nameserver;
    char *domain;
    char *record_type;
    char *class;
    int verbose;
    int port;
};

/**
 * @brief build DNS packet
 *
 * This function builds a "normal" DNS packet for putting it in the body of a CoAP packet.
 *
 * \param[in] args contains the commandline arguments from the user
 * \param[out] buffer store the DNS packet that is build here
 * \return the length of the DNS packet
 */

int prepare_dns_packet(struct arguments *args, void *buffer) {
    ldns_resolver *res;     // keeps a list of nameservers, and can perform queries for us
    ldns_rdf *domain;       // store the name the user specifies when calling the program
    ldns_pkt *p;            // dns packet, e.g. a complete query or an answer
    ldns_pkt *q;
    ldns_rr_list *a_records;       // list of DNS Resource Records
    ldns_rdf *ns;           // nameserver
    ldns_buffer *buf;
    enum ldns_enum_rdf_type type = LDNS_RDF_TYPE_A;

    // interpret command line arguments as ldns structures
    domain = ldns_dname_new_frm_str(args->domain);
    if (args->nameserver[0] == '[') {
        type = LDNS_RDF_TYPE_AAAA;
        char *tmp = malloc(sizeof(char) * strlen(args->nameserver));
        strcpy(tmp, args->nameserver);
        tmp++;
        tmp[strlen(tmp) - 1] = '\0';
        ns = ldns_rdf_new_frm_str(type, tmp);
        free(--tmp);
    } else {
        ns = ldns_rdf_new_frm_str(type, args->nameserver);
    }

    // create a resolver structure
    res = ldns_resolver_new();

    // push a new nameserver to the resolver
    ldns_resolver_push_nameserver(res, ns);
    ldns_rdf_deep_free(ns);
    // set the port the resolver should use
    ldns_resolver_set_port(res, args->port);

    // create the DNS packet
    q = ldns_pkt_query_new(domain, ldns_get_rr_type_by_name(args->record_type), ldns_get_rr_class_by_name(args->class),
                           LDNS_RD);

    buf = ldns_buffer_new(512);

    // convert the packet in a buffer in wire format
    ldns_pkt2buffer_wire(buf, q);

    // interpret buffer as 8bit int
    uint8_t *data = ldns_buffer_begin(buf);

    size_t len = ldns_buffer_position(buf);

    // copy the local data buffer to the buffer in main
    memcpy(buffer, data, len);

    ldns_resolver_deep_free(res);
    ldns_pkt_free(q);
    ldns_buffer_free(buf);

    return len;
}

// The options that the program supports
static struct argp_option options[] = {
        {"verbose", 'v', 0,      0, "Produce verbose output", 0},
        {"port",    'p', "PORT", 0, "Set port number",        0},
        {0}
};

/**
 * @brief parse options
 *
 * This function parses the commandline arguments from the user.
 *
 * \param[in] key indicates the type of argument or action, i.e. a specific character or a constant defined by the argp library
 * \param[in] arg points to the argument value associated with key
 * \param[in] state provides the state of the argument parser, e.g. the current argument index
 * \return success or failure of the parsing operation
 * @retval 0 success
 * @retval other Non-zero: predefined error codes
 */
static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct arguments *args = state->input;

    switch (key) {
        case 'v':
            args->verbose = 1;
            break;
        case 'p':
            if (arg) {
                args->port = atoi(arg);
            }
            break;
        case ARGP_KEY_ARG:
            if (state->arg_num == 0) {
                // first argument is a nameserver
                if (arg[0] == '@') {
                    char *test = arg + 1;
                    enum ldns_enum_rdf_type type;
                    int value;

                    if (test[0] == '[') {
                        char *tmp = malloc(sizeof(char) * strlen(test));
                        strcpy(tmp, test);
                        tmp++;
                        tmp[strlen(tmp) - 1] = '\0';
                        type = LDNS_RDF_TYPE_AAAA;
                        *test = *tmp;
                        value = 6;
                        free(--tmp);
                    } else {
                        type = LDNS_RDF_TYPE_A;
                        value = 4;
                    }

                    ldns_rdf *rdf = ldns_rdf_new_frm_str(type, test);
                    if(!rdf){
                        printf("%s is not a valid IPv%d address\n", test, value);
                        exit(1);
                    }
                    ldns_rdf_deep_free(rdf);
                    args->nameserver = arg + 1; // Skip the '@'
                } else {    // interpret first argument as domain name, record type or class
                    if (ldns_dname_new_frm_str(arg)) {
                        args->domain = arg;
                    } else if (ldns_get_rr_type_by_name(arg)) {
                        args->record_type = arg;
                    } else if (ldns_get_rr_class_by_name(arg)) {
                        args->class = arg;
                    } else {
                        printf("%s is no valid argument\n", arg);
                        exit(1);
                    }
                }
            } else if (state->arg_num == 1) {   // interpret second argument as domain name, record type or class
                ldns_rdf *rdf = ldns_dname_new_frm_str(arg);
                if (rdf && args->domain == NULL) {
                    args->domain = arg;
                    ldns_rdf_deep_free(rdf);
                } else if (ldns_get_rr_type_by_name(arg) && args->record_type == NULL) {
                    args->record_type = arg;
                } else if (ldns_get_rr_class_by_name(arg) && args->class == NULL) {
                    args->class = arg;
                } else {
                    printf("%s is no valid argument\n", arg);
                    exit(1);
                }
            } else if (state->arg_num == 2) {   // interpret third argument as record type or class
                if (ldns_get_rr_type_by_name(arg) && args->record_type == NULL) {
                    args->record_type = arg;
                } else if (ldns_get_rr_class_by_name(arg) && args->class == NULL) {
                    args->class = arg;
                } else {
                    printf("%s is no valid argument\n", arg);
                    exit(1);
                }
            } else if (state->arg_num == 3) {   // interpret fourth argument as class
                if (ldns_get_rr_class_by_name(arg) && args->class == NULL) {
                    args->class = arg;
                } else {
                    printf("%s is no valid argument\n", arg);
                    exit(1);
                }
            } else {
                // Too many arguments
                argp_usage(state);
            }
            break;
        case ARGP_KEY_END:
            if (state->arg_num > 4) {
                argp_usage(state);
            }
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

// Argument parsing structure
static struct argp argp = {
        options,      // options list
        parse_opt,    // function to parse options
        "[@server] [domain] [record_type]", // Program usage pattern
        "A command-line tool that sends a DNS request over CoAP to a server", // Program documentation
};

/**
 * @brief main function
 *
 * This function prepares the commandline argument, sets up libcoap, sends the CoD packet and waits for a response.
 *
 * \param[in] argc stores the number of commandline arguments passed by the user including the name of the program
 * \param[in] argv is an array of character pointers listing all the arguments
 * \return success or failure of the program
 * @retval 0 success
 * @retval 1 failure
 */
int main(int argc, char **argv) {
    struct arguments args;
    args.verbose = 0;
    args.port = -1;
    args.nameserver = NULL;
    args.domain = NULL;
    args.record_type = NULL;
    args.class = NULL;

    // Parse the arguments
    argp_parse(&argp, argc, argv, 0, 0, &args);

    // default values
    if (args.nameserver == NULL) args.nameserver = "127.0.0.1";
    if (args.domain == NULL) args.domain = "example.org";
    if (args.record_type == NULL) args.record_type = "A";
    if (args.class == NULL) args.class = "IN";
    if (args.port == -1) args.port = 8000;

    int return_code = 0;
    coap_context_t *context = NULL;
    coap_session_t *session = NULL;
    coap_pdu_t *pdu = NULL;
    coap_pdu_t *resp_pdu = NULL;
    coap_address_t dst;
    coap_uri_t uri;
    coap_addr_info_t *addr_info;
    coap_optlist_t *optlist = NULL;

    // always needs to be done at the beginning
    coap_startup();
    // set log level depending on verbose option
    coap_set_log_level(args.verbose ? COAP_LOG_DEBUG : COAP_LOG_WARN);

    // from domain name create a server uri with a specific syntax
    char *server_uri = malloc(sizeof(char) * 100);
    sprintf(server_uri, "coap://%s:%d/dns", args.nameserver, args.port);

    if (args.verbose) {
        printf("server IP: %s\nport: %d\ndomain: %s\nrecord type: %s\nclass: %s\n", args.nameserver, args.port,
               args.domain, args.record_type, args.class);
    }

    // parse server uri into uri components
    int len = coap_split_uri((const unsigned char *) server_uri, strlen(server_uri), &uri);
    if (len != 0) {
        coap_log_warn("Failed to parse uri '%s'\n", server_uri);
        return_code = 1;
        goto cleanup;
    }


    /* resolve destination address where server should be sent */
    addr_info = coap_resolve_address_info(&uri.host, uri.port, uri.port, uri.port, uri.port,
                                          AF_UNSPEC, 1 << uri.scheme,
                                          COAP_RESOLVE_TYPE_REMOTE);

    bool fail = true;
    if (addr_info) {
        fail = false;
        *(&dst) = addr_info->addr;
    }

    if (fail) {
        coap_log_warn("Failed to resolve address %*.*s\n", (int) uri.host.length, (int) uri.host.length,
                      (const char *) uri.host.s);
        goto cleanup;
    }

    if (!(context = coap_new_context(NULL))) {
        coap_log_warn("Could not create CoAP context!\n");
        return_code = 1;
        goto cleanup;
    }

    // if wanting to use DTLS, use the following instructions (currently not supported):
    //
    // https://github.com/obgm/libcoap/blob/develop/examples/lwip/client-coap.c
    // char* dtls_id = "client_identity";
    // char* dtls_key = "psk";

    // coap_dtls_cpsk_t dtls_psk;
    // memset(&dtls_psk, 0, sizeof(dtls_psk));

    // dtls_psk.version = COAP_DTLS_CPSK_SETUP_VERSION;
    // char client_sni[256];
    // snprintf(client_sni, sizeof(client_sni), "%*.*s", (int)uri.host.length, (int)uri.host.length, uri.host.s);
    // dtls_psk.client_sni = client_sni;
    // dtls_psk.psk_info.identity.s = (const uint8_t *)dtls_id;
    // dtls_psk.psk_info.identity.length = strlen(dtls_id);
    // dtls_psk.psk_info.key.s = (const uint8_t *)dtls_key;
    // dtls_psk.psk_info.key.length = strlen(dtls_key);

    // session = coap_new_client_session_psk2(context, NULL, &dst, COAP_PROTO_DTLS, &dtls_psk);

    // create a new coap session that saves the current state
    session = coap_new_client_session(context, NULL, &dst, COAP_PROTO_UDP);
    if (!session) {
        coap_log_warn("Could not create CoAP session!\n");
        return_code = 1;
        goto cleanup;
    }
    // register response handler which is called when a CoAP packet is received
    coap_register_response_handler(context, handle_response);

    // create a PDU = Protocol Data Unit
    pdu = coap_pdu_init(
            COAP_MESSAGE_CON, /* COAP_MESSAGE_NON */
            COAP_REQUEST_CODE_FETCH,
            0,
            coap_session_max_pdu_size(session)
    );
    if (!pdu) {
        printf("Could not create CoAP PDU!\n");
        return_code = 1;
        goto cleanup;
    }

    // buffer where the DNS packet will be put in -> later put in the body of the CoAP packet
    unsigned char buffer[DNS_PACKET_SIZE];

    // coap_add_option(pdu, COAP_OPTION_URI_PATH, uri.path.length, uri.path.s);

    // takes a coap_uri_t and then adds CoAP options into the optlist_chain
    int res = coap_uri_into_options(&uri, &dst, &optlist, 1, buffer, DNS_PACKET_SIZE);
    if (res < 0) {
        printf("Failed to create options!\n");
        return_code = 1;
        goto cleanup;
    }

    // https://datatracker.ietf.org/doc/html/rfc7252#section-5.10
    // 553 = application/dns-message
    // buffer needs at least size 2
    len = coap_encode_var_safe(buffer, DNS_PACKET_SIZE, DIGDOC_CF_DNS);

    // add optlist to the given optlist_chain
    coap_insert_optlist(&optlist, coap_new_optlist(COAP_OPTION_CONTENT_FORMAT, len, buffer));
    coap_insert_optlist(&optlist, coap_new_optlist(COAP_OPTION_ACCEPT, len, buffer));

    // optlist of optlist_chain is added to the PDU
    res = coap_add_optlist_pdu(pdu, &optlist);
    if (res == 0) {
        printf("Failed to add options to PDU!\n");
        return_code = 1;
        goto cleanup;
    }

    // prepare the DNS packet
    len = prepare_dns_packet(&args, buffer);

    if (len < 0) {
        printf("Failed to build DNS packet!\n");
        return_code = 1;
        goto cleanup;
    }

    // add the DNS packet to the body of the CoAP packet
    coap_add_data(pdu, len, buffer);
    // timer for query time
    // TODO: start = clock();
    // send the CoAP packet
    // coap_send(session, pdu);
    int processing_return = 0;
    processing_return = coap_send_recv(session, pdu, &resp_pdu, 3000);
    printf("result: %d\n", processing_return);
    // wait for receiving a CoAP response
    /*while (!handler_called && processing_return != -1) {
        if(coap_can_exit(context)) printf("can!\n");
        else printf("cant\n");
        processing_return = coap_io_process(context, COAP_IO_WAIT);
        if(coap_can_exit(context)) printf("can!\n");
        else printf("cant\n");
    }*/

    cleanup:
    if (optlist) coap_delete_optlist(optlist);
    if (session) coap_session_release(session);
    if (context) coap_free_context(context);
    if(addr_info) coap_free_address_info(addr_info);
    if(server_uri) free(server_uri);

    coap_cleanup();

    return return_code;
}
