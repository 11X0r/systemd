/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "dhcp-protocol.h"
#include "networkd-link-bus.h"
#include "sd-bus.h"
#include "sd-dhcp-client.h"

#include "bus-object.h"

extern const BusObjectImplementation dhcp_client_object;

int dhcp_client_callback_bus(sd_dhcp_client *client, int event, void *userdata);
const char* dhcp_client_state_to_string(DHCPState s) _const_;
