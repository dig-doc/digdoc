#include <coap3/coap.h>

#ifndef DIGDOCPROJECT_COAP_HELPER_H
#define DIGDOCPROJECT_COAP_HELPER_H

#endif //DIGDOCPROJECT_COAP_HELPER_H

typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dns_header_t;

void parse_dns_response(const uint8_t *response, size_t response_len);
size_t build_dns_query(const char *domain, uint8_t *dns_query);
int resolve_address(const char *host, const char *service, coap_address_t *dst);