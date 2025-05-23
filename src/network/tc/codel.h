/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2019 VMware, Inc. */
#pragma once

#include "qdisc.h"

typedef struct ControlledDelay {
        QDisc meta;

        usec_t interval_usec;
        usec_t target_usec;
        usec_t ce_threshold_usec;
        uint32_t packet_limit;
        int ecn;
} ControlledDelay;

DEFINE_QDISC_CAST(CODEL, ControlledDelay);
extern const QDiscVTable codel_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_controlled_delay_u32);
CONFIG_PARSER_PROTOTYPE(config_parse_controlled_delay_usec);
CONFIG_PARSER_PROTOTYPE(config_parse_controlled_delay_bool);
