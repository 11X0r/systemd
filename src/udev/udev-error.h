/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include "sd-device.h"

int device_add_errno(sd_device *dev, int error);
int device_add_exit_status(sd_device *dev, int status);
int device_add_signal(sd_device *dev, int signo);
