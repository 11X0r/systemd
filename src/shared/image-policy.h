/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct ImagePolicy ImagePolicy;

#include "dissect-image.h"

typedef enum PartitionPolicyFlags {
        PARTITION_POLICY_VERITY               = 1 << 0, /* must exist, use as verity */
        PARTITION_POLICY_SIGNED               = 1 << 1, /* must exist, use as signed verity */
        PARTITION_POLICY_ENCRYPTED            = 1 << 2, /* must exist, use as LUKS encryption */
        PARTITION_POLICY_UNPROTECTED          = 1 << 3, /* must exist, use without encryption/verity */
        PARTITION_POLICY_UNUSED               = 1 << 4, /* must exist, don't use */
        PARTITION_POLICY_ABSENT               = 1 << 5, /* must not exist */
        PARTITION_POLICY_OPEN                 = PARTITION_POLICY_VERITY|PARTITION_POLICY_SIGNED|PARTITION_POLICY_ENCRYPTED|PARTITION_POLICY_UNPROTECTED|PARTITION_POLICY_UNUSED|PARTITION_POLICY_ABSENT,
        _PARTITION_POLICY_USE_MASK            = PARTITION_POLICY_OPEN,

        PARTITION_POLICY_READ_ONLY_OFF        = 1 << 6, /* State of GPT partition flag "read-only" must be on */
        PARTITION_POLICY_READ_ONLY_ON         = 1 << 7,
        _PARTITION_POLICY_READ_ONLY_MASK      = PARTITION_POLICY_READ_ONLY_OFF|PARTITION_POLICY_READ_ONLY_ON,
        PARTITION_POLICY_GROWFS_OFF           = 1 << 8, /* State of GPT partition flag "growfs" must be on */
        PARTITION_POLICY_GROWFS_ON            = 1 << 9,
        _PARTITION_POLICY_GROWFS_MASK         = PARTITION_POLICY_GROWFS_OFF|PARTITION_POLICY_GROWFS_ON,
        _PARTITION_POLICY_PFLAGS_MASK         = _PARTITION_POLICY_READ_ONLY_MASK|_PARTITION_POLICY_GROWFS_MASK,

        _PARTITION_POLICY_FLAGS_INVALID       = -EINVAL,
} PartitionPolicyFlags;

typedef struct PartitionPolicy {
        PartitionDesignator designator;
        PartitionPolicyFlags flags;
} PartitionPolicy;

struct ImagePolicy {
        size_t n_policies;
        PartitionPolicy policies[]; /* sorted by designator, hence suitable for binary search */
};

/* Default policies for various usecases */
extern const ImagePolicy image_policy_sysext;
extern const ImagePolicy image_policy_container;
extern const ImagePolicy image_policy_service;
extern const ImagePolicy image_policy_host;

PartitionPolicyFlags image_policy_get(const ImagePolicy *policy, PartitionDesignator designator);
PartitionPolicyFlags image_policy_get_exhaustively(const ImagePolicy *policy, PartitionDesignator designator);

PartitionPolicyFlags partition_policy_flags_from_string(const char *s);
int partition_policy_flags_to_string(PartitionPolicyFlags flags, char **ret);

int image_policy_from_string(const char *s, ImagePolicy **ret);
int image_policy_to_string(const ImagePolicy *policy, char **ret);

bool image_policy_equal(const ImagePolicy *a, const ImagePolicy *b);

static inline ImagePolicy* image_policy_free(ImagePolicy *p) {
        return mfree(p);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(ImagePolicy*, image_policy_free);
