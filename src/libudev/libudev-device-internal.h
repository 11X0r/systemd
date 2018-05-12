/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2008-2012 Kay Sievers <kay@vrfy.org>
  Copyright 2015 Tom Gundersen <teg@jklm.no>
***/

#include "libudev.h"
#include "sd-device.h"

#include "libudev-private.h"

/**
 * udev_device:
 *
 * Opaque object representing one kernel sys device.
 */
struct udev_device {
        struct udev *udev;

        /* real device object */
        sd_device *device;

        /* legacy */
        int refcount;

        struct udev_device *parent;
        bool parent_set;

        struct udev_list properties;
        uint64_t properties_generation;
        struct udev_list tags;
        uint64_t tags_generation;
        struct udev_list devlinks;
        uint64_t devlinks_generation;
        bool properties_read:1;
        bool tags_read:1;
        bool devlinks_read:1;
        struct udev_list sysattrs;
        bool sysattrs_read;
};

struct udev_device *udev_device_new(struct udev *udev);
