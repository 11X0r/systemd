/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2014 Tom Gundersen <teg@jklm.no>
***/

typedef struct Veth Veth;

#include "netdev/netdev.h"

struct Veth {
        NetDev meta;

        char *ifname_peer;
        struct ether_addr *mac_peer;
};

DEFINE_NETDEV_CAST(VETH, Veth);
extern const NetDevVTable veth_vtable;
