/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "conf-parser.h"
#include "in-addr-util.h"

typedef struct FirewallContext FirewallContext;

int fw_ctx_new(FirewallContext **ret);
int fw_ctx_new_full(FirewallContext **ret, bool init_tables);
FirewallContext *fw_ctx_free(FirewallContext *ctx);

DEFINE_TRIVIAL_CLEANUP_FUNC(FirewallContext *, fw_ctx_free);

int fw_add_masquerade(
                FirewallContext **ctx,
                bool add,
                int af,
                const union in_addr_union *source,
                unsigned source_prefixlen);

int fw_add_local_dnat(
                FirewallContext **ctx,
                bool add,
                int af,
                int protocol,
                uint16_t local_port,
                const union in_addr_union *remote,
                uint16_t remote_port,
                const union in_addr_union *previous_remote);

typedef struct NFTSet {
        int nfproto;
        char *table;
        char *set;
} NFTSet;

typedef struct NFTSetContext {
        NFTSet *sets;
        size_t n_sets;
} NFTSetContext;

int nft_set_add(NFTSetContext *s, int nfproto, const char *table, const char *set);
void nft_set_context_free(NFTSetContext *s);
int nft_set_context_dup(const NFTSetContext *src, NFTSetContext *dst);

const char *nfproto_to_string(int i) _const_;
int nfproto_from_string(const char *s) _pure_;

int nft_set_element_modify_in_addr_open(
                FirewallContext **ctx,
                bool add,
                NFTSet *nft_set,
                int af,
                const union in_addr_union *address,
                unsigned int prefixlen);

CONFIG_PARSER_PROTOTYPE(config_parse_nft_set);
