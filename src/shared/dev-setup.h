/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2010-2012 Lennart Poettering
***/

#include <sys/types.h>

int dev_setup(const char *prefix, uid_t uid, gid_t gid);
