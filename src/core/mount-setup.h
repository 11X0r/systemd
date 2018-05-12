/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
***/

#include <stdbool.h>

int mount_setup_early(void);
int mount_setup(bool loaded_policy);

int mount_cgroup_controllers(char ***join_controllers);

bool mount_point_is_api(const char *path);
bool mount_point_ignore(const char *path);
