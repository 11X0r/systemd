/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

int log_facility_unshifted_to_string_alloc(int i, char **s);
int log_facility_unshifted_from_string(const char *s);
bool log_facility_unshifted_is_valid(int faciliy);

/* These ones understands the usual syslog levels (EMERG…DEBUG) */
int log_level_to_string_alloc(int i, char **ret);
int log_level_from_string(const char *s);
bool log_level_is_valid(int level);

/* These ones, also support the special level "null" (LOG_NULL) to indicate that logging shall be turned off */
int log_max_level_to_string_alloc(int i, char **ret);
int log_max_level_from_string(const char *s);
bool log_max_level_is_valid(int level);

int syslog_parse_priority(const char **p, int *priority, bool with_facility);

bool log_namespace_name_valid(const char *s);
