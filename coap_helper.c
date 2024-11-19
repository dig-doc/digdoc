#include <netdb.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <coap3/coap.h>
#include "coap_helper.h"

void parse_dns_response(const uint8_t *response, size_t response_len) {
    printf("received DNS response.\n");

    if (response_len < sizeof(dns_header_t)) {
        printf("Invalid DNS response.\n");
        return;
    }

    // dns rfc https://www.ietf.org/rfc/rfc1035.txt
    size_t offset = sizeof(dns_header_t);

    if (response_len < offset) {
        printf("Invalid DNS response.\n");
        return;
    }

    // DNS header
    dns_header_t dns_header;
    memcpy(&dns_header, response, sizeof(dns_header_t));

    dns_header.qdcount = ntohs(dns_header.qdcount);
    dns_header.ancount = ntohs(dns_header.ancount);

    // skip question section
    for (int i = 0; i < dns_header.qdcount; i++) {
        while (offset < response_len && response[offset] != 0) {
            if (response[offset] >= 192) {
                offset += 2;
                break;
            } else {
                offset += response[offset] + 1;
            }
        }
        offset += 5;
    }

    // answer section
    for (int i = 0; i < dns_header.ancount; i++) {
        if (response[offset] >= 192) {
            offset += 2;
        } else {
            while (offset < response_len && response[offset] != 0) {
                offset += response[offset] + 1;
            }
            offset += 1;
        }

        if (offset + 10 > response_len) {
            printf("Invalid DNS answer.\n");
            return;
        }

        uint16_t type = ntohs(*(uint16_t *)(response + offset));
        offset += 10; // Skip TYPE, CLASS, TTL, RDLENGTH

        if (type == 1 && offset + 4 <= response_len) {
            // A record
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, response + offset, ip_str, INET_ADDRSTRLEN);
            printf("IP: %s\n", ip_str);
        }
        offset += 4; // Skip RDATA
    }

}

size_t build_dns_query(const char *domain, uint8_t *dns_query) {
    size_t dns_query_len = 0;

    // dns header
    dns_header_t dns_header = {
            htons(0x1234),
            htons(0x0100),
            htons(1),
            0, 0, 0
    };

    memcpy(dns_query + dns_query_len, &dns_header, sizeof(dns_header));
    dns_query_len += sizeof(dns_header);

    // dns format https://www.ietf.org/rfc/rfc1035.txt
    while (*domain) {
        size_t len = strcspn(domain, ".");
        dns_query[dns_query_len++] = (uint8_t) len;
        memcpy(dns_query + dns_query_len, domain, len);
        dns_query_len += len;
        domain += len;
        if (*domain == '.') domain++;
    }

    dns_query[dns_query_len++] = 0x00;

    // A
    uint16_t qtype = htons(1);
    memcpy(dns_query + dns_query_len, &qtype, sizeof(qtype));
    dns_query_len += sizeof(qtype);

    // IN
    uint16_t qclass = htons(1);
    memcpy(dns_query + dns_query_len, &qclass, sizeof(qclass));
    dns_query_len += sizeof(qclass);

    return dns_query_len;
}

// from https://github.com/obgm/libcoap-minimal/blob/main/common.cc
int resolve_address(const char *host, const char *service, coap_address_t *dst) {

    struct addrinfo *res, *ainfo;
    struct addrinfo hints;
    int error, len = -1;

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
            default:;
        }
    }

    finish:
    freeaddrinfo(res);
    return len;
}