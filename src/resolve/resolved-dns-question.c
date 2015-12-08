/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include "alloc-util.h"
#include "dns-domain.h"
#include "resolved-dns-question.h"

DnsQuestion *dns_question_new(unsigned n) {
        DnsQuestion *q;

        assert(n > 0);

        q = malloc0(offsetof(DnsQuestion, keys) + sizeof(DnsResourceKey*) * n);
        if (!q)
                return NULL;

        q->n_ref = 1;
        q->n_allocated = n;

        return q;
}

DnsQuestion *dns_question_ref(DnsQuestion *q) {
        if (!q)
                return NULL;

        assert(q->n_ref > 0);
        q->n_ref++;
        return q;
}

DnsQuestion *dns_question_unref(DnsQuestion *q) {
        if (!q)
                return NULL;

        assert(q->n_ref > 0);

        if (q->n_ref == 1) {
                unsigned i;

                for (i = 0; i < q->n_keys; i++)
                        dns_resource_key_unref(q->keys[i]);
                free(q);
        } else
                q->n_ref--;

        return  NULL;
}

int dns_question_add(DnsQuestion *q, DnsResourceKey *key) {
        unsigned i;
        int r;

        assert(key);

        if (!q)
                return -ENOSPC;

        for (i = 0; i < q->n_keys; i++) {
                r = dns_resource_key_equal(q->keys[i], key);
                if (r < 0)
                        return r;
                if (r > 0)
                        return 0;
        }

        if (q->n_keys >= q->n_allocated)
                return -ENOSPC;

        q->keys[q->n_keys++] = dns_resource_key_ref(key);
        return 0;
}

int dns_question_matches_rr(DnsQuestion *q, DnsResourceRecord *rr, const char *search_domain) {
        unsigned i;
        int r;

        assert(rr);

        if (!q)
                return 0;

        for (i = 0; i < q->n_keys; i++) {
                r = dns_resource_key_match_rr(q->keys[i], rr, search_domain);
                if (r != 0)
                        return r;
        }

        return 0;
}

int dns_question_matches_cname(DnsQuestion *q, DnsResourceRecord *rr, const char *search_domain) {
        unsigned i;
        int r;

        assert(rr);

        if (!q)
                return 0;

        for (i = 0; i < q->n_keys; i++) {
                r = dns_resource_key_match_cname(q->keys[i], rr, search_domain);
                if (r != 0)
                        return r;
        }

        return 0;
}

int dns_question_is_valid_for_query(DnsQuestion *q) {
        const char *name;
        unsigned i;
        int r;

        if (!q)
                return 0;

        if (q->n_keys <= 0)
                return 0;

        if (q->n_keys > 65535)
                return 0;

        name = DNS_RESOURCE_KEY_NAME(q->keys[0]);
        if (!name)
                return 0;

        /* Check that all keys in this question bear the same name */
        for (i = 1; i < q->n_keys; i++) {
                assert(q->keys[i]);

                r = dns_name_equal(DNS_RESOURCE_KEY_NAME(q->keys[i]), name);
                if (r <= 0)
                        return r;
        }

        return 1;
}

int dns_question_contains(DnsQuestion *a, DnsResourceKey *k) {
        unsigned j;
        int r;

        assert(k);

        if (!a)
                return 0;

        for (j = 0; j < a->n_keys; j++) {
                r = dns_resource_key_equal(a->keys[j], k);
                if (r != 0)
                        return r;
        }

        return 0;
}

int dns_question_is_equal(DnsQuestion *a, DnsQuestion *b) {
        unsigned j;
        int r;

        if (!a)
                return !b || b->n_keys == 0;
        if (!b)
                return a->n_keys == 0;

        /* Checks if all keys in a are also contained b, and vice versa */

        for (j = 0; j < a->n_keys; j++) {
                r = dns_question_contains(b, a->keys[j]);
                if (r <= 0)
                        return r;
        }

        for (j = 0; j < b->n_keys; j++) {
                r = dns_question_contains(a, b->keys[j]);
                if (r <= 0)
                        return r;
        }

        return 1;
}

int dns_question_cname_redirect(DnsQuestion *q, const DnsResourceRecord *cname, DnsQuestion **ret) {
        _cleanup_(dns_question_unrefp) DnsQuestion *n = NULL;
        bool same = true;
        unsigned i;
        int r;

        assert(cname);
        assert(ret);
        assert(IN_SET(cname->key->type, DNS_TYPE_CNAME, DNS_TYPE_DNAME));

        if (!q) {
                n = dns_question_new(0);
                if (!n)
                        return -ENOMEM;

                *ret = n;
                n = 0;
                return 0;
        }

        for (i = 0; i < q->n_keys; i++) {
                _cleanup_free_ char *destination = NULL;
                const char *d;

                if (cname->key->type == DNS_TYPE_CNAME)
                        d = cname->cname.name;
                else {
                        r = dns_name_change_suffix(DNS_RESOURCE_KEY_NAME(q->keys[i]), DNS_RESOURCE_KEY_NAME(cname->key), cname->dname.name, &destination);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                continue;

                        d = destination;
                }

                r = dns_name_equal(DNS_RESOURCE_KEY_NAME(q->keys[i]), d);
                if (r < 0)
                        return r;

                if (r == 0) {
                        same = false;
                        break;
                }
        }

        if (same) {
                /* Shortcut, the names are already right */
                *ret = dns_question_ref(q);
                return 0;
        }

        n = dns_question_new(q->n_keys);
        if (!n)
                return -ENOMEM;

        /* Create a new question, and patch in the new name */
        for (i = 0; i < q->n_keys; i++) {
                _cleanup_(dns_resource_key_unrefp) DnsResourceKey *k = NULL;

                k = dns_resource_key_new_redirect(q->keys[i], cname);
                if (!k)
                        return -ENOMEM;

                r = dns_question_add(n, k);
                if (r < 0)
                        return r;
        }

        *ret = n;
        n = NULL;

        return 1;
}

const char *dns_question_first_name(DnsQuestion *q) {

        if (!q)
                return NULL;

        if (q->n_keys < 1)
                return NULL;

        return DNS_RESOURCE_KEY_NAME(q->keys[0]);
}

int dns_question_new_address(DnsQuestion **ret, int family, const char *name) {
        _cleanup_(dns_question_unrefp) DnsQuestion *q = NULL;
        int r;

        assert(ret);
        assert(name);

        if (!IN_SET(family, AF_INET, AF_INET6, AF_UNSPEC))
                return -EAFNOSUPPORT;

        q = dns_question_new(family == AF_UNSPEC ? 2 : 1);
        if (!q)
                return -ENOMEM;

        if (family != AF_INET6) {
                _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

                key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, name);
                if (!key)
                        return -ENOMEM;

                r = dns_question_add(q, key);
                if (r < 0)
                        return r;
        }

        if (family != AF_INET) {
                _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

                key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_AAAA, name);
                if (!key)
                        return -ENOMEM;

                r = dns_question_add(q, key);
                if (r < 0)
                        return r;
        }

        *ret = q;
        q = NULL;

        return 0;
}

int dns_question_new_reverse(DnsQuestion **ret, int family, const union in_addr_union *a) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_question_unrefp) DnsQuestion *q = NULL;
        _cleanup_free_ char *reverse = NULL;
        int r;

        assert(ret);
        assert(a);

        if (!IN_SET(family, AF_INET, AF_INET6, AF_UNSPEC))
                return -EAFNOSUPPORT;

        r = dns_name_reverse(family, a, &reverse);
        if (r < 0)
                return r;

        q = dns_question_new(1);
        if (!q)
                return -ENOMEM;

        key = dns_resource_key_new_consume(DNS_CLASS_IN, DNS_TYPE_PTR, reverse);
        if (!key)
                return -ENOMEM;

        reverse = NULL;

        r = dns_question_add(q, key);
        if (r < 0)
                return r;

        *ret = q;
        q = NULL;

        return 0;
}

int dns_question_new_service(DnsQuestion **ret, const char *name, bool with_txt) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_question_unrefp) DnsQuestion *q = NULL;
        int r;

        assert(ret);
        assert(name);

        q = dns_question_new(1 + with_txt);
        if (!q)
                return -ENOMEM;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_SRV, name);
        if (!key)
                return -ENOMEM;

        r = dns_question_add(q, key);
        if (r < 0)
                return r;

        if (with_txt) {
                dns_resource_key_unref(key);
                key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_TXT, name);
                if (!key)
                        return -ENOMEM;

                r = dns_question_add(q, key);
                if (r < 0)
                        return r;
        }

        *ret = q;
        q = NULL;

        return 0;
}
