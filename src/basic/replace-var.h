/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering
***/

char *replace_var(const char *text, char *(*lookup)(const char *variable, void *userdata), void *userdata);
