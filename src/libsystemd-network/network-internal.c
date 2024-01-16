/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <arpa/inet.h>
#include <linux/if.h>
#include <netinet/ether.h>

#include "sd-ndisc.h"

#include "alloc-util.h"
#include "dhcp-lease-internal.h"
#include "extract-word.h"
#include "hexdecoct.h"
#include "in-addr-util.h"
#include "log.h"
#include "network-internal.h"
#include "parse-util.h"

size_t serialize_in_addrs(FILE *f,
                          const struct in_addr *addresses,
                          size_t size,
                          bool *with_leading_space,
                          bool (*predicate)(const struct in_addr *addr)) {
        assert(f);
        assert(addresses);

        size_t count = 0;
        bool _space = false;
        if (!with_leading_space)
                with_leading_space = &_space;

        for (size_t i = 0; i < size; i++) {
                if (predicate && !predicate(&addresses[i]))
                        continue;

                if (*with_leading_space)
                        fputc(' ', f);
                fputs(IN4_ADDR_TO_STRING(&addresses[i]), f);
                count++;
                *with_leading_space = true;
        }

        return count;
}

int deserialize_in_addrs(struct in_addr **ret, const char *string) {
        _cleanup_free_ struct in_addr *addresses = NULL;
        int size = 0;

        assert(ret);
        assert(string);

        for (;;) {
                _cleanup_free_ char *word = NULL;
                struct in_addr *new_addresses;
                int r;

                r = extract_first_word(&string, &word, NULL, 0);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                new_addresses = reallocarray(addresses, size + 1, sizeof(struct in_addr));
                if (!new_addresses)
                        return -ENOMEM;
                else
                        addresses = new_addresses;

                r = inet_pton(AF_INET, word, &(addresses[size]));
                if (r <= 0)
                        continue;

                size++;
        }

        *ret = size > 0 ? TAKE_PTR(addresses) : NULL;

        return size;
}

void serialize_in6_addrs(FILE *f, const struct in6_addr *addresses, size_t size, bool *with_leading_space) {
        assert(f);
        assert(addresses);
        assert(size);

        bool _space = false;
        if (!with_leading_space)
                with_leading_space = &_space;

        for (size_t i = 0; i < size; i++) {
                if (*with_leading_space)
                        fputc(' ', f);
                fputs(IN6_ADDR_TO_STRING(&addresses[i]), f);
                *with_leading_space = true;
        }
}

int deserialize_in6_addrs(struct in6_addr **ret, const char *string) {
        _cleanup_free_ struct in6_addr *addresses = NULL;
        int size = 0;

        assert(ret);
        assert(string);

        for (;;) {
                _cleanup_free_ char *word = NULL;
                struct in6_addr *new_addresses;
                int r;

                r = extract_first_word(&string, &word, NULL, 0);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                new_addresses = reallocarray(addresses, size + 1, sizeof(struct in6_addr));
                if (!new_addresses)
                        return -ENOMEM;
                else
                        addresses = new_addresses;

                r = inet_pton(AF_INET6, word, &(addresses[size]));
                if (r <= 0)
                        continue;

                size++;
        }

        *ret = TAKE_PTR(addresses);

        return size;
}

int serialize_dnr(FILE *f, const ResolverData *resolvers, bool *with_leading_space) {
        int r;

        bool _space = false;
        if (!with_leading_space)
                with_leading_space = &_space;

        int n = 0;
        LIST_FOREACH(resolvers, i, resolvers) {
                _cleanup_strv_free_ char **names = NULL;
                r = dns_resolvers_to_dot_strv(resolvers, &names);
                if (r < 0)
                        return -ENOMEM;
                if (r > 0)
                        fputstrv(f, names, NULL, with_leading_space);
                n += r;
        }
        return n;
}

int deserialize_dnr(ResolverData **ret, const char *string) {
        int r;

        assert(ret);
        assert(string);

        _cleanup_(dhcp_resolver_data_free_allp) ResolverData *resolvers = NULL;
        int n = 0;

        for (;;) {
                _cleanup_free_ char *word = NULL;
                struct in_addr_full addr;

                r = extract_first_word(&string, &word, NULL, 0);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;
                r = in_addr_port_ifindex_name_from_string_auto(word,
                                &addr.family, &addr.address, &addr.port, &addr.ifindex, &addr.server_name);
                if (r < 0)
                        return r;

                _cleanup_free_ char *auth_name = strdup(addr.server_name);
                if (!auth_name)
                        return -ENOMEM;

                _cleanup_free_ struct in_addr *addr_in = memdup(&addr.address.in, sizeof(*addr_in));
                if (!addr_in)
                        return -ENOMEM;

                _cleanup_(dhcp_resolver_data_free_allp) ResolverData *resolver = new(ResolverData, 1);
                if (!resolver)
                        return -ENOMEM;

                *resolver = (ResolverData) {
                        .priority = n+1, /* not serialized, but this will preserve the order */
                        .auth_name = TAKE_PTR(auth_name),
                        .addrs = addr_in,
                        .n_addrs = 1, //FIXME coalesce these?
                        .transports = SD_DNS_ALPN_DOT, //FIXME not serialized, assumed DoT
                        .port = addr.port,
                        .dohpath = NULL, //FIXME not serialized
                        /* list fields are zero-initialized */
                };

                LIST_APPEND(resolvers, resolvers, TAKE_PTR(resolver));
                n++;
        }
        *ret = TAKE_PTR(resolvers);
        return n;
}

void serialize_dhcp_routes(FILE *f, const char *key, sd_dhcp_route **routes, size_t size) {
        assert(f);
        assert(key);
        assert(routes);
        assert(size);

        fprintf(f, "%s=", key);

        for (size_t i = 0; i < size; i++) {
                struct in_addr dest, gw;
                uint8_t length;

                assert_se(sd_dhcp_route_get_destination(routes[i], &dest) >= 0);
                assert_se(sd_dhcp_route_get_gateway(routes[i], &gw) >= 0);
                assert_se(sd_dhcp_route_get_destination_prefix_length(routes[i], &length) >= 0);

                fprintf(f, "%s,%s%s",
                        IN4_ADDR_PREFIX_TO_STRING(&dest, length),
                        IN4_ADDR_TO_STRING(&gw),
                        i < size - 1 ? " ": "");
        }

        fputs("\n", f);
}

int deserialize_dhcp_routes(struct sd_dhcp_route **ret, size_t *ret_size, const char *string) {
        _cleanup_free_ struct sd_dhcp_route *routes = NULL;
        size_t size = 0;

        assert(ret);
        assert(ret_size);
        assert(string);

         /* WORD FORMAT: dst_ip/dst_prefixlen,gw_ip */
        for (;;) {
                _cleanup_free_ char *word = NULL;
                char *tok, *tok_end;
                unsigned n;
                int r;

                r = extract_first_word(&string, &word, NULL, 0);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                if (!GREEDY_REALLOC(routes, size + 1))
                        return -ENOMEM;

                tok = word;

                /* get the subnet */
                tok_end = strchr(tok, '/');
                if (!tok_end)
                        continue;
                *tok_end = '\0';

                r = inet_aton(tok, &routes[size].dst_addr);
                if (r == 0)
                        continue;

                tok = tok_end + 1;

                /* get the prefixlen */
                tok_end = strchr(tok, ',');
                if (!tok_end)
                        continue;

                *tok_end = '\0';

                r = safe_atou(tok, &n);
                if (r < 0 || n > 32)
                        continue;

                routes[size].dst_prefixlen = (uint8_t) n;
                tok = tok_end + 1;

                /* get the gateway */
                r = inet_aton(tok, &routes[size].gw_addr);
                if (r == 0)
                        continue;

                size++;
        }

        *ret_size = size;
        *ret = TAKE_PTR(routes);

        return 0;
}

int serialize_dhcp_option(FILE *f, const char *key, const void *data, size_t size) {
        _cleanup_free_ char *hex_buf = NULL;

        assert(f);
        assert(key);
        assert(data);

        hex_buf = hexmem(data, size);
        if (!hex_buf)
                return -ENOMEM;

        fprintf(f, "%s=%s\n", key, hex_buf);

        return 0;
}
