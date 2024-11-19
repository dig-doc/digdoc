#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <coap3/coap.h> /* handle coap protocol */
#include <argp.h> /* argument parsing */

#include <arpa/inet.h> /* ip parsing */
#include "coap3/coap_debug.h"
#include "mdns.h" /* create/parse dns packets */

// NOTE: the path "/dns" is important here
//   the proxy does not adhere to the recommendation
//   of using "/" as path
// #define COAP_SERVER_URI "coap://[::1]:8080/dns"
// #define COAP_SERVER_URI "coap://127.0.0.1:8080/dns"

// https://github.com/packetzero/dnsparser/blob/master/src/dnsparse.cpp

char* entry_to_string(mdns_entry_type_t entry) {
  switch (entry) {
    case MDNS_ENTRYTYPE_QUESTION: return "QUESTION";
    case MDNS_ENTRYTYPE_ANSWER: return "ANSWER";
    case MDNS_ENTRYTYPE_AUTHORITY: return "AUTHORITY";
    case MDNS_ENTRYTYPE_ADDITIONAL: return "ADDITIONAL";
  }
}
char* type_to_string(mdns_record_type_t type) {
  switch (type) {
    case MDNS_RECORDTYPE_RESERVED: return "RESERVED";
    case MDNS_RECORDTYPE_A:        return "A";
    case MDNS_RECORDTYPE_NS:       return "NS";
    case MDNS_RECORDTYPE_CNAME:    return "CNAME";
    case MDNS_RECORDTYPE_PTR:      return "PTR";
    case MDNS_RECORDTYPE_TXT:      return "TXT";
    case MDNS_RECORDTYPE_AAAA:     return "AAAA";
    case MDNS_RECORDTYPE_SRV:      return "SRV";
    case MDNS_RECORDTYPE_ANY:      return "ANY";
    case MDNS_RECORDTYPE_URI:      return "URI";
  }
}
char* class_to_string(mdns_class_t class) {
  switch (class) {
    case MDNS_CLASS_IN:   return "IN";
    case MDNS_CLASS_CH:   return "CH";
    case MDNS_CLASS_HS:   return "HS";
    case MDNS_CLASS_NONE: return "NONE";
    case MDNS_CLASS_ANY:  return "ANY";
  }
}
void print_v4_record(const void* data, size_t size,
  size_t name_offset, size_t name_length, size_t record_offset,
  size_t record_length) {
  struct sockaddr_in addr_v4;
  mdns_record_parse_a(data, size, record_offset, record_length, &addr_v4);

  char buffer[1024];
  mdns_string_t name = mdns_string_extract(data, size, &name_offset, buffer, 1024);

  char ip_buffer[16];
  inet_ntop(AF_INET, &addr_v4.sin_addr, ip_buffer, 16);

  printf("IP: %s NAME: %.*s\n", inet_ntoa(addr_v4.sin_addr), (int)name.length, name.str);
}
void print_cname_record(const void* data, size_t size,
  size_t name_offset, size_t name_length, size_t record_offset,
  size_t record_length) {
  struct sockaddr_in addr_v4;

  char cname_buffer[1024];
  mdns_string_t cname = mdns_string_extract(data, size, &record_offset, cname_buffer, 1024);
  char buffer[1024];
  mdns_string_t name = mdns_string_extract(data, size, &name_offset, buffer, 1024);

  printf("NAME: %.*s CNAME: %.*s\n", (int)name.length, name.str, (int)cname.length, cname.str);
}
void print_v6_record(const void* data, size_t size,
  size_t name_offset, size_t name_length, size_t record_offset,
  size_t record_length) {
  struct sockaddr_in6 addr_v6;
  mdns_record_parse_aaaa(data, size, record_offset, record_length, &addr_v6);

  char buffer[1024];
  mdns_string_t name = mdns_string_extract(data, size, &name_offset, buffer, 1024);

  char ip_buffer[64];
  inet_ntop(AF_INET6, &addr_v6.sin6_addr, ip_buffer, 64);

  printf("IP: %s NAME: %.*s\n", ip_buffer, (int)name.length, name.str);
}

int print_record(
  int _sock, const struct sockaddr* _from, size_t _addrlen,
  mdns_entry_type_t entry, uint16_t query_id, uint16_t rtype,
  uint16_t rclass, uint32_t ttl, const void* data, size_t size,
  size_t name_offset, size_t name_length, size_t record_offset,
  size_t record_length, void* user_data
) {
  printf("%s type:%s class:%s ttl:%d\n", entry_to_string(entry), type_to_string(rtype), class_to_string(rclass), ttl);

  switch (rtype) {
    case MDNS_RECORDTYPE_A:
      print_v4_record(data, size, name_offset, name_length, record_offset, record_length);
      break;
    case MDNS_RECORDTYPE_AAAA:
      print_v6_record(data, size, name_offset, name_length, record_offset, record_length);
      break;
    case MDNS_RECORDTYPE_CNAME:
      print_cname_record(data, size, name_offset, name_length, record_offset, record_length);
      break;
  }
  
  return 0; /* 0 => keep parsing following records */
}

coap_response_t handle_response(coap_session_t *session, const coap_pdu_t *sentPdu, const coap_pdu_t *receivedPdu, const coap_mid_t messageId) {
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

  uint16_t query_id = mdns_ntohs(data++);
  uint16_t flags = mdns_ntohs(data++);
  uint16_t questions = mdns_ntohs(data++);
  uint16_t answer_rrs = mdns_ntohs(data++);
  uint16_t authority_rrs = mdns_ntohs(data++);
  uint16_t additional_rrs = mdns_ntohs(data++);
  int i;
  for (i = 0; i < questions; ++i) {
    size_t offset = MDNS_POINTER_DIFF(data, buffer);
    if (!mdns_string_skip(buffer, len, &offset))
      return 0;
    data = (const uint16_t*)MDNS_POINTER_OFFSET_CONST(buffer, offset);
    // Record type and class not used, skip
    // uint16_t rtype = mdns_ntohs(data++);
    // uint16_t rclass = mdns_ntohs(data++);
    data += 2;
  }

  size_t records = 0;
  size_t total_records = 0;
  size_t offset = MDNS_POINTER_DIFF(data, buffer);
  records = mdns_records_parse(0, NULL, 0, buffer, len, &offset,
              MDNS_ENTRYTYPE_ANSWER, query_id, answer_rrs, print_record, NULL);
  total_records += records;
  if (records != answer_rrs)
    coap_log_warn("Parsed too few answer records");

  records = mdns_records_parse(0, NULL, 0, buffer, len, &offset,
              MDNS_ENTRYTYPE_AUTHORITY, query_id, authority_rrs, print_record, NULL);
  total_records += records;
  if (records != authority_rrs)
    coap_log_warn("Parsed too few authority records");

  records = mdns_records_parse(0, NULL, 0, buffer, len, &offset,
              MDNS_ENTRYTYPE_ADDITIONAL, query_id, additional_rrs, print_record, NULL);
  total_records += records;
  if (records != additional_rrs)
    coap_log_warn("Parsed too few additional records");

  return COAP_RESPONSE_OK;
}

enum dns_flags {
  DNS_FLAGS_RD = 1/* Recursion Desired */
};

// adapted from mdns.h (see mdns_query_send)
int build_dns_packet(mdns_record_type_t type, const char* name, void* buffer, int capacity) {
  struct mdns_query_t query = {.type = type, .name = name, .length = strlen(name)};
  struct mdns_query_t* queries = &query;
  int count = 1;
  int query_id = 0;

  // Ask for a unicast response since it's a one-shot query
  uint16_t rclass = MDNS_CLASS_IN;

  struct mdns_header_t* header = (struct mdns_header_t*)buffer;
  // Query ID
  header->query_id = htons((unsigned short)query_id);
  // Flags
  header->flags = DNS_FLAGS_RD;
  // Questions
  header->questions = htons((unsigned short)count);
  // No answer, authority or additional RRs
  header->answer_rrs = 0;
  header->authority_rrs = 0;
  header->additional_rrs = 0;
  // Fill in questions
  void* data = MDNS_POINTER_OFFSET(buffer, sizeof(struct mdns_header_t));
  for (size_t iq = 0; iq < count; ++iq) {
    // Name string
    data = mdns_string_make(buffer, capacity, data, queries[iq].name, queries[iq].length, 0);
    if (!data)
        return -1;
    size_t remain = capacity - MDNS_POINTER_DIFF(data, buffer);
    if (remain < 4)
        return -1;
    // Record type
    data = mdns_htons(data, queries[iq].type);
    //! Optional unicast response based on local port, class IN
    data = mdns_htons(data, rclass);
  }

  return (int)MDNS_POINTER_DIFF(data, buffer);
}



const char *argp_program_version = "digdoc 1.0";
const char *argp_program_bug_address = "<leonie.seelisch@mailbox.tu-dresden.de>";

enum ARGP_KEYS {
  ARGP_URI = 1
};
/* The options we understand. */
static struct argp_option options[] = {
  {"verbose", 'v', 0, 0, "Output debug information" },
  {"host", 0, 0, OPTION_DOC, "domain query e.g. example.org" },
  {"type", 0, 0, OPTION_DOC, "record type e.g. A, AAAA, CNAME" },
  {"server", 0, 0, OPTION_DOC, "DNS server uri e.g. coap://<host>:<port>/<path>" },
  { 0 }
};

/* Used by main to communicate with parse_opt. */
struct arguments
{
  bool verbose;
  char *server_uri;
  char *host;
  mdns_record_type_t type;
};

/* Parse a single option. */
static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  /* Get the input argument from argp_parse, which we
     know is a pointer to our arguments structure. */
  struct arguments *arguments = state->input;

  switch (key) {
    case 'v':
      arguments->verbose = true;
      break;

    case ARGP_KEY_ARG:
      if (state->arg_num >= 3)
        /* Too many arguments. */
        argp_usage (state);

      if (*arg == '@')
        arguments->server_uri = arg+1;
      else if (strcmp(arg, "A") == 0)
        arguments->type = MDNS_RECORDTYPE_A;
      else if (strcmp(arg, "AAAA") == 0)
        arguments->type = MDNS_RECORDTYPE_AAAA;
      else if (strcmp(arg, "CNAME") == 0)
        arguments->type = MDNS_RECORDTYPE_CNAME;
      else if (strcmp(arg, "*") == 0)
        arguments->type = MDNS_RECORDTYPE_ANY;
      else if (arguments->host == 0)
        arguments->host = arg;
      else
        argp_usage (state);
      break;

    case ARGP_KEY_END:
      if (state->arg_num < 1)
        /* Not enough arguments. */
        argp_usage (state);
      break;

    default:
      return ARGP_ERR_UNKNOWN;
    }
  return 0;
}

/* Our argp parser. */
static struct argp argp = { options, parse_opt, "[@server] [type] host", "digdoc -- sending DNS over COAP" };

int main(int argc, char *argv[]) {
  struct arguments arguments;
  memset(&arguments, 0, sizeof(struct arguments));
  

  /* Default values. */
  arguments.type = MDNS_RECORDTYPE_A;
  arguments.server_uri = "coap://[::1]:8080/dns";

  /* Parse our arguments; every option seen by parse_opt will
     be reflected in arguments. */
  argp_parse (&argp, argc, argv, 0, 0, &arguments);

  if (arguments.verbose) {
    printf("host: %s\n", arguments.host);
    printf("server: %s\n", arguments.server_uri);
  }

  int returnCode = 0;
  coap_context_t* context = NULL;
  coap_session_t* session = NULL;
  coap_pdu_t* pdu = NULL;
  coap_address_t dst;
  coap_uri_t uri;
  coap_addr_info_t *addr_info;
  coap_optlist_t *optlist = NULL;

  coap_startup();
  coap_set_log_level(arguments.verbose ? COAP_LOG_DEBUG : COAP_LOG_WARN);

  int len = coap_split_uri((const unsigned char *)arguments.server_uri, strlen(arguments.server_uri), &uri);
  if (len != 0) {
    coap_log_warn("Failed to parse uri '%s'\n", arguments.server_uri);
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

  // TODO find reasonable upper bound
  unsigned char buffer[1024];

  // coap_add_option(pdu, COAP_OPTION_URI_PATH, uri.path.length, uri.path.s);
  int res = coap_uri_into_options(&uri, &dst, &optlist, 1, buffer, 1024);
  if (res < 0) {
    printf("Failed to create options!\n");
    returnCode = 1;
    goto cleanup;
  }

  // https://datatracker.ietf.org/doc/html/rfc7252#section-5.10
  // 553 = application/dns-message
  // buffer needs at least size 2
  len = coap_encode_var_safe(buffer, 1024, 553);

  coap_insert_optlist(&optlist, coap_new_optlist(COAP_OPTION_CONTENT_FORMAT, len, buffer));
  coap_insert_optlist(&optlist, coap_new_optlist(COAP_OPTION_ACCEPT, len, buffer));

  res = coap_add_optlist_pdu(pdu, &optlist);
  if (res == 0) {
    printf("Failed to add options to PDU!\n");
    returnCode = 1;
    goto cleanup;
  }

  /* Add the DNS query payload (e.g., "example.org") */
  len = build_dns_packet(arguments.type, arguments.host, buffer, 1024);
  if (len < 0) {
    printf("Failed to build DNS packet!\n");
    returnCode = 1;
    goto cleanup;
  }
  coap_add_data(pdu, len, buffer);

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
