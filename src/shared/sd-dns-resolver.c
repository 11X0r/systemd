/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-dns-resolver.h"

#include "macro.h"
#include "unaligned.h"
#include "socket-netlink.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"

void sd_dns_resolver_done(sd_dns_resolver *res) {
        free(res->auth_name);
        free(res->addrs);
        free(res->dohpath);
}

void sd_dns_resolver_clear(sd_dns_resolver *res) {
        res->auth_name = mfree(res->auth_name);
        res->addrs = mfree(res->addrs);
        res->dohpath = mfree(res->dohpath);
}

sd_dns_resolver *sd_dns_resolver_free(sd_dns_resolver *res) {
        sd_dns_resolver_done(res);
        return mfree(res);
}

void sd_dns_resolver_array_free(sd_dns_resolver resolvers[], size_t n) {
        assert(resolvers || n == 0);

        FOREACH_ARRAY(res, resolvers, n)
                sd_dns_resolver_done(res);

        free(resolvers);
}

int sd_dns_resolver_prio_compare(const sd_dns_resolver *a, const sd_dns_resolver *b) {
        return a->priority - b->priority;
}

int sd_dns_resolver_get_priority(const sd_dns_resolver *res, uint16_t *priority) {
        assert_return(res, -EINVAL);
        assert_return(priority, -EINVAL);

        *priority = res->priority;
        return 0;
}

int sd_dns_resolver_get_adn(const sd_dns_resolver *res, const char **adn) {
        assert_return(res, -EINVAL);
        assert_return(adn, -EINVAL);

        /* Without adn only Do53 can be supported */
        if (!res->auth_name)
                return -ENODATA;

        *adn = res->auth_name;
        return 0;
}

int sd_dns_resolver_get_addrs(const sd_dns_resolver *res, int *family, const union in_addr_union **addrs, size_t *n) {
        assert_return(res, -EINVAL);
        assert_return(family, -EINVAL);
        assert_return(addrs, -EINVAL);
        assert_return(n, -EINVAL);

        /* ADN-only mode has no addrs */
        if (res->n_addrs == 0)
                return -ENODATA;

        *family = res->family;
        *addrs = res->addrs;
        *n = res->n_addrs;

        return 0;
}

int sd_dns_resolver_get_transports(const sd_dns_resolver *res, DNSALPNFlags *transports) {
        assert_return(res, -EINVAL);
        assert_return(transports, -EINVAL);

        /* ADN-only mode has no transports */
        if (!res->transports)
                return -ENODATA;

        *transports = res->transports;
        return 0;
}

int sd_dns_resolver_get_port(const sd_dns_resolver *res, uint16_t *port) {
        assert_return(res, -EINVAL);
        assert_return(port, -EINVAL);

        /* port = 0 is the default port */
        *port = res->port;
        return 0;
}

int sd_dns_resolver_get_dohpath(const sd_dns_resolver *res, const char **dohpath) {
        assert_return(res, -EINVAL);
        assert_return(dohpath, -EINVAL);

        /* only present in DoH resolvers */
        if (!res->dohpath)
                return -ENODATA;

        *dohpath = res->dohpath;
        return 0;
}


static const char* const dns_svc_param_key_table[_DNS_SVC_PARAM_KEY_MAX_DEFINED] = {
        [DNS_SVC_PARAM_KEY_MANDATORY]       = "mandatory",
        [DNS_SVC_PARAM_KEY_ALPN]            = "alpn",
        [DNS_SVC_PARAM_KEY_NO_DEFAULT_ALPN] = "no-default-alpn",
        [DNS_SVC_PARAM_KEY_PORT]            = "port",
        [DNS_SVC_PARAM_KEY_IPV4HINT]        = "ipv4hint",
        [DNS_SVC_PARAM_KEY_ECH]             = "ech",
        [DNS_SVC_PARAM_KEY_IPV6HINT]        = "ipv6hint",
        [DNS_SVC_PARAM_KEY_DOHPATH]         = "dohpath",
        [DNS_SVC_PARAM_KEY_OHTTP]           = "ohttp",
};
DEFINE_STRING_TABLE_LOOKUP_TO_STRING(dns_svc_param_key, int);

const char *format_dns_svc_param_key(uint16_t i, char buf[static DECIMAL_STR_MAX(uint16_t)+3]) {
        const char *p = dns_svc_param_key_to_string(i);
        if (p)
                return p;

        return snprintf_ok(buf, DECIMAL_STR_MAX(uint16_t)+3, "key%i", i);
}

int dnr_parse_svc_params(const uint8_t *option, size_t len, sd_dns_resolver *resolver) {
        size_t offset = 0;
        int r;

        assert(resolver);

        DNSALPNFlags transports = 0;
        uint16_t port = 0;
        _cleanup_free_ char *dohpath = NULL;
        bool alpn = false;

        uint16_t lastkey = 0;
        while (offset < len) {
                if (offset + 4 > len)
                        return -EBADMSG;

                uint16_t key = unaligned_read_be16(&option[offset]);
                offset += 2;

                /* RFC9460 § 2.2 SvcParam MUST appear in strictly increasing numeric order */
                if (lastkey >= key)
                        return -EBADMSG;
                lastkey = key;

                uint16_t plen = unaligned_read_be16(&option[offset]);
                offset += 2;
                if (offset + plen > len)
                        return -EBADMSG;

                switch (key) {
                /* Mandatory keys must be understood by the client, otherwise the record should be discarded.
                 * Automatic mandatory keys must not appear in the mandatory parameter, so these are all
                 * supplementary. We don't understand any supplementary keys, so if the mandatory parameter
                 * is present, we cannot use this record.*/
                case DNS_SVC_PARAM_KEY_MANDATORY:
                        if (plen > 0)
                                return -EBADMSG;
                        break;

                case DNS_SVC_PARAM_KEY_ALPN:
                        if (plen == 0)
                                return 0;
                        alpn = true; /* alpn is required. Record that the requirement is met. */

                        size_t poff = offset;
                        size_t pend = offset + plen;
                        while (poff < pend) {
                                uint8_t alen = option[poff++];
                                if (poff + alen > len)
                                        return -EBADMSG;
                                if (alen == 3 && strneq((const char*) &option[poff], "dot", alen))
                                        SET_FLAG(transports, SD_DNS_ALPN_DOT, true);
                                if (alen == 2 && strneq((const char*) &option[poff], "h2", alen))
                                        SET_FLAG(transports, SD_DNS_ALPN_HTTP_2_TLS, true);
                                if (alen == 2 && strneq((const char*) &option[poff], "h3", alen))
                                        SET_FLAG(transports, SD_DNS_ALPN_HTTP_3, true);
                                if (alen == 3 && strneq((const char*) &option[poff], "doq", alen))
                                        SET_FLAG(transports, SD_DNS_ALPN_DOQ, true);
                                poff += alen;
                        }
                        if (poff != pend)
                                return -EBADMSG;
                        break;

                case DNS_SVC_PARAM_KEY_PORT:
                        if (plen != 2)
                                return -EBADMSG;
                        port = unaligned_read_be16(&option[offset]);
                        /* Server should indicate default port by omitting this param */
                        if (port == 0)
                                return -EBADMSG;
                        break;

                /* RFC9463 § 5.1 service params MUST NOT include ipv4hint/ipv6hint */
                case DNS_SVC_PARAM_KEY_IPV4HINT:
                case DNS_SVC_PARAM_KEY_IPV6HINT:
                        return -EBADMSG;

                case DNS_SVC_PARAM_KEY_DOHPATH: {
                        r = make_cstring((const char*) &option[offset], plen,
                                        MAKE_CSTRING_REFUSE_TRAILING_NUL, &dohpath);
                        if (ERRNO_IS_NEG_RESOURCE(r))
                                return r;
                        if (r < 0)
                                return -EBADMSG;
                        break;
                }

                default:
                        break;
                }
                offset += plen;
        }
        if (offset != len)
                return -EBADMSG;

        /* DNR cannot be used without alpn */
        if (!alpn)
                return -EBADMSG;

        /* RFC9461 § 5: If the [SvcParam] indicates support for HTTP, "dohpath" MUST be present. */
        if (!dohpath && (FLAGS_SET(transports, SD_DNS_ALPN_HTTP_2_TLS) ||
                        FLAGS_SET(transports, SD_DNS_ALPN_HTTP_3)))
                return -EBADMSG;

        /* No useful transports */
        if (!transports)
                return 0;

        resolver->transports = transports;
        resolver->port = port;
        free_and_replace(resolver->dohpath, dohpath);
        return transports;
}

int sd_dns_resolvers_to_dot_addrs(const sd_dns_resolver *resolvers, size_t n_resolvers,
                struct in_addr_full ***ret_addrs, size_t *ret_n_addrs) {
        assert(ret_addrs);
        assert(ret_n_addrs);

        struct in_addr_full **addrs = NULL;
        size_t n = 0;
        CLEANUP_ARRAY(addrs, n, in_addr_full_array_free);

        FOREACH_ARRAY(res, resolvers, n_resolvers) {
                if (!FLAGS_SET(res->transports, SD_DNS_ALPN_DOT))
                        continue;

                FOREACH_ARRAY(i, res->addrs, res->n_addrs) {
                        _cleanup_(in_addr_full_freep) struct in_addr_full *addr = NULL;
                        int r;

                        addr = new0(struct in_addr_full, 1);
                        if (!addr)
                                return -ENOMEM;
                        if (!GREEDY_REALLOC(addrs, n+1))
                                return -ENOMEM;

                        r = free_and_strdup(&addr->server_name, res->auth_name);
                        if (r < 0)
                                return r;
                        addr->family = res->family;
                        addr->port = res->port;
                        addr->address = *i;

                        addrs[n++] = TAKE_PTR(addr);
                }
        }

        *ret_addrs = TAKE_PTR(addrs);
        *ret_n_addrs = n;
        return n;
}

int sd_dns_resolvers_to_dot_strv(const sd_dns_resolver *resolvers, size_t n_resolvers, char ***ret_names) {
        assert(ret_names);
        int r;

        _cleanup_strv_free_ char **names = NULL;
        size_t len = 0;

        struct in_addr_full **addrs = NULL;
        size_t n = 0;
        CLEANUP_ARRAY(addrs, n, in_addr_full_array_free);

        r = sd_dns_resolvers_to_dot_addrs(resolvers, n_resolvers, &addrs, &n);
        if (r < 0)
                return r;

        FOREACH_ARRAY(addr, addrs, n) {
                const char *name = in_addr_full_to_string(*addr);
                if (!name)
                        return -ENOMEM;
                r = strv_extend_with_size(&names, &len, name);
                if (r < 0)
                        return r;

        }

        *ret_names = TAKE_PTR(names);
        return len;
}
