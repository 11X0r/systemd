/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
***/

#include "dbus-device.h"
#include "device.h"
#include "unit.h"

const sd_bus_vtable bus_device_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("SysFSPath", "s", NULL, offsetof(Device, sysfs), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_VTABLE_END
};
