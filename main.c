#include <stdio.h>
#include <stdlib.h>
#include <argp.h>
#include <string.h>
#include <ldns/ldns.h>
#include <coap3/coap.h>
#include <coap3/coap_debug.h>
#include <time.h>

#define DNS_PACKAGE_SIZE 512

clock_t start;

// TODO: get away that OPTION on the help page (--help and --usage), make -h work

void print_output(ldns_pkt *pkt, size_t dns_length, int query_time){
    ldns_rr_list *rrList = ldns_pkt_question(pkt);
    if(rrList->_rr_count > 0){
        printf("\n;; QUESTION SECTION:\n;");
    }
    ldns_rr_list_print(stdout, rrList);
    rrList = ldns_pkt_answer(pkt);
    if(rrList->_rr_count > 0){
        printf("\n;; ANSWER SECTION:\n");
    }
    ldns_rr_list_print(stdout, rrList);
    rrList = ldns_pkt_authority(pkt);
    if(rrList->_rr_count > 0){
        printf("\n;; AUTHORITY SECTION:\n");
    }
    ldns_rr_list_print(stdout, rrList);
    rrList = ldns_pkt_additional(pkt);
    if(rrList->_rr_count > 0){
        printf("\n;; ADDITIONAL SECTION:\n");
    }
    ldns_rr_list_print(stdout, rrList);
    printf("\nQuery time: %dus", query_time);
    printf("\nDNS PKT SIZE rcvd: %ld\n", dns_length);
}

coap_response_t handle_response(coap_session_t *session, const coap_pdu_t *sentPdu, const coap_pdu_t *receivedPdu, const coap_mid_t messageId) {
    clock_t end = clock();

    (void) session;
    (void) sentPdu;
    (void) messageId;

    coap_show_pdu(LOG_INFO, receivedPdu);

    const uint8_t *buffer;
    size_t len, off, total;
    if (!coap_get_data_large(receivedPdu, &len, &buffer, &off, &total)) {
        printf("No response.\n");
        return COAP_RESPONSE_OK;
    }
    const uint16_t* data = (const uint16_t*)buffer;

    ldns_buffer *ldnsBuffer;
    ldns_pkt *pkt;
    ldnsBuffer = ldns_buffer_new(DNS_PACKAGE_SIZE);
    ldns_buffer_write(ldnsBuffer, data, len);
    ldns_buffer2pkt_wire(&pkt, ldnsBuffer);
    print_output(pkt, total, ((double )(end-start))/CLOCKS_PER_SEC*1000*1000);

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

int do_dns_stuff(struct arguments args, void *buffer){
    ldns_resolver *res;     // keeps a list of nameservers, and can perform queries for us
    ldns_rdf *domain;       // store the name the user specifies when calling the program
    ldns_pkt *p;            // dns packet, e.g. a complete query or an answer
    ldns_pkt *q;
    ldns_rr_list *a_records;       // list of DNS Resource Records
    ldns_rdf *ns;           // nameserver
    ldns_buffer *buf;
    enum ldns_enum_rdf_type type = LDNS_RDF_TYPE_A;

    domain = ldns_dname_new_frm_str(args.domain);
    if(args.nameserver[0] == '[') {
        type = LDNS_RDF_TYPE_AAAA;
        char *tmp = malloc(sizeof(char) * strlen(args.nameserver));
        strcpy(tmp, args.nameserver);
        tmp++;
        tmp[strlen(tmp)-1] = '\0';
        ns = ldns_rdf_new_frm_str(type, tmp);
    } else{
        ns = ldns_rdf_new_frm_str(type, args.nameserver);
    }

    res = ldns_resolver_new();

    ldns_resolver_push_nameserver(res, ns);
    ldns_resolver_set_port(res, args.port);

    q = ldns_pkt_query_new(domain, ldns_get_rr_type_by_name(args.record_type), ldns_get_rr_class_by_name(args.class), LDNS_RD);

    buf = ldns_buffer_new(512);

    ldns_pkt2buffer_wire(buf, q);
//    ldns_pkt2buffer_str(buf, q);

    uint8_t *data = ldns_buffer_begin(buf);

    size_t len = ldns_buffer_position(buf);

    memcpy(buffer, data, len);
//    buffer = data;
//    printf("buffer: %p\n", buffer);
    return len;
//    printf("%s\n", ldns_buffer2str(buf));
//    printf("hm\n");
/*
    p = ldns_resolver_query(res, domain, ldns_get_rr_type_by_name(args.record_type), ldns_get_rr_class_by_name(args.class), LDNS_RD);

    a_records = ldns_pkt_authority(p);

    ldns_rr_list_print(stdout, a_records);*/
}

// The options that the program supports
static struct argp_option options[] = {
        {"verbose", 'v', 0, 0, "Produce verbose output", 0},
        {"port", 'p', "PORT", 0, "Set port number", 0},
        { 0 }
};

// Function to parse options
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
                if (arg[0] == '@') {
                    char *test = arg+1;
                    if(test[0] == '['){
                        char *tmp = malloc(sizeof(char) * strlen(test));
                        strcpy(tmp, test);
                        tmp++;
                        tmp[strlen(tmp)-1] = '\0';
                        if(!(ldns_rdf_new_frm_str(LDNS_RDF_TYPE_AAAA, tmp))){
                            printf("%s is not a valid IPv6 address\n", test);
                            exit(1);
                        }
                    } else if(!(ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, test))){
                        printf("%s is not a valid IPv4 address\n", test);
                        exit(1);
                    }
                    args->nameserver = arg + 1; // Skip the '@'
                } else {
                    if(ldns_dname_new_frm_str(arg)){
                        args->domain = arg;
                    } else if(ldns_get_rr_type_by_name(arg)){
                        args->record_type = arg;
                    } else if(ldns_get_rr_class_by_name(arg)){
                        args->class = arg;
                    } else{
                        printf("%s is no valid argument\n", arg);
                        exit(1);
                    }
                }
            } else if (state->arg_num == 1) {
                if(ldns_dname_new_frm_str(arg) && args->domain == NULL){
                    args->domain = arg;
                } else if(ldns_get_rr_type_by_name(arg) && args->record_type == NULL){
                    args->record_type = arg;
                } else if(ldns_get_rr_class_by_name(arg) && args->class == NULL){
                    args->class = arg;
                } else{
                    printf("%s is no valid argument\n", arg);
                    exit(1);
                }
            } else if (state->arg_num == 2) {
                if(ldns_get_rr_type_by_name(arg) && args->record_type == NULL){
                    args->record_type = arg;
                } else if(ldns_get_rr_class_by_name(arg) && args->class == NULL){
                    args->class = arg;
                } else{
                    printf("%s is no valid argument\n", arg);
                    exit(1);
                }
            } else if (state->arg_num == 3) {
                if(ldns_get_rr_class_by_name(arg) && args->class == NULL){
                    args->class = arg;
                } else{
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
        "A commandline tool that sends a DNS request over CoAP to a server", // Program documentation
};

// Main program
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

    if(args.nameserver == NULL) args.nameserver = "127.0.0.1";
    if(args.domain == NULL) args.domain = "example.org";
    if(args.record_type == NULL) args.record_type = "A";
    if(args.class == NULL) args.class = "IN";
    if(args.port == -1) args.port = 8000;

    int returnCode = 0;
    coap_context_t* context = NULL;
    coap_session_t* session = NULL;
    coap_pdu_t* pdu = NULL;
    coap_address_t dst;
    coap_uri_t uri;
    coap_addr_info_t *addr_info;
    coap_optlist_t *optlist = NULL;

    coap_startup();
    coap_set_log_level(args.verbose ? COAP_LOG_DEBUG : COAP_LOG_WARN);

    char *server_uri = malloc(sizeof(char) * 100);
    sprintf(server_uri, "coap://%s:%d/dns", args.nameserver, args.port);

    if(args.verbose){
        printf("server IP: %s\nport: %d\ndomain: %s\nrecord type: %s\nclass: %s\n", args.nameserver, args.port, args.domain, args.record_type, args.class);
    }

    int len = coap_split_uri((const unsigned char *)server_uri, strlen(server_uri), &uri);
    if (len != 0) {
        coap_log_warn("Failed to parse uri '%s'\n", server_uri);
        returnCode = 1;
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
    coap_free_address_info(addr_info);

    if (fail) {
        coap_log_warn("Failed to resolve address %*.*s\n", (int)uri.host.length, (int)uri.host.length, (const char *)uri.host.s);
        goto cleanup;
    }

    if (!(context = coap_new_context(NULL))) {
        coap_log_warn("Could not create CoAP context!\n");
        returnCode = 1;
        goto cleanup;
    }

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
    session = coap_new_client_session(context, NULL, &dst, COAP_PROTO_UDP); /* COAP_PROTO_DTLS / COAP_PROTO_UDP */
    if (!session) {
        coap_log_warn("Could not create CoAP session!\n");
        returnCode = 1;
        goto cleanup;
    }
    coap_register_response_handler(context, handle_response);

    pdu = coap_pdu_init(
            COAP_MESSAGE_CON, /* COAP_MESSAGE_NON */
            COAP_REQUEST_CODE_FETCH,
            0,
            coap_session_max_pdu_size(session)
    );
    if (!pdu) {
        printf("Could not create CoAP PDU!\n");
        returnCode = 1;
        goto cleanup;
    }

    unsigned char buffer[DNS_PACKAGE_SIZE];

    // coap_add_option(pdu, COAP_OPTION_URI_PATH, uri.path.length, uri.path.s);
    int res = coap_uri_into_options(&uri, &dst, &optlist, 1, buffer, DNS_PACKAGE_SIZE);
    if (res < 0) {
        printf("Failed to create options!\n");
        returnCode = 1;
        goto cleanup;
    }

    // https://datatracker.ietf.org/doc/html/rfc7252#section-5.10
    // 553 = application/dns-message
    // buffer needs at least size 2
    len = coap_encode_var_safe(buffer, DNS_PACKAGE_SIZE, 553);

    coap_insert_optlist(&optlist, coap_new_optlist(COAP_OPTION_CONTENT_FORMAT, len, buffer));
    coap_insert_optlist(&optlist, coap_new_optlist(COAP_OPTION_ACCEPT, len, buffer));

    res = coap_add_optlist_pdu(pdu, &optlist);
    if (res == 0) {
        printf("Failed to add options to PDU!\n");
        returnCode = 1;
        goto cleanup;
    }

    /* Add the DNS query payload (e.g., "example.org") */
//    len = build_dns_packet(arguments.type, arguments.host, buffer, 1024);
    len = do_dns_stuff(args, buffer);

    if (len < 0) {
        printf("Failed to build DNS packet!\n");
        returnCode = 1;
        goto cleanup;
    }

    coap_add_data(pdu, len, buffer);
    start = clock();
    coap_send(session, pdu);
    // while (true)

    coap_io_process(context, COAP_IO_WAIT);

    cleanup:
    if(optlist) coap_delete_optlist(optlist);
    if(session) coap_session_release(session);
    if(context) coap_free_context(context);
    coap_cleanup();

    return returnCode;
}
