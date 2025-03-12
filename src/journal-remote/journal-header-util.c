/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "escape.h"
#include "journal-header-util.h"
#include "string-util.h"
#include "strv.h"

/* HTTP header name can contains:
- Alphanumeric characters: a-z, A-Z, and 0-9
- The following special characters: - and _ */
#define VALID_HEADER_NAME_CHARS \
        DIGITS LETTERS "_-"

#define VALID_HEADER_NAME_LENGTH 40

#define VALID_HEADER_VALUE_CHARS \
        DIGITS LETTERS "_ :;.,\\/'\"?!(){}[]@<>=-+*#$&`|~^%"

static bool header_name_is_valid(const char *e) {
        if (!e)
                return false;

        if (strlen(e) > VALID_HEADER_NAME_LENGTH)
                return false;

        return in_charset(e, VALID_HEADER_NAME_CHARS);
}

static bool header_value_is_valid(const char *e) {
        if (!e)
                return false;

        return in_charset(e, VALID_HEADER_VALUE_CHARS);
}

int header_put(OrderedHashmap **headers, const char *name, const char *value) {
        assert(headers);

        if (!header_value_is_valid(value))
                return -EINVAL;

        if (!header_name_is_valid(name))
                return -EINVAL;

        return string_strv_ordered_hashmap_put(headers, name, value);
}

int config_parse_header(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        OrderedHashmap **headers = ASSERT_PTR(data);
        char *unescaped, *t;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                /* an empty string clears the previous assignments. */
                *headers = ordered_hashmap_free(*headers);
                return 1;
        }

        r = cunescape(rvalue, 0, &unescaped);
        if (r < 0)
                return log_syntax(unit, LOG_WARNING, filename, line, r,
                                  "Failed to unescape headers: %s", rvalue);

        t = strchr(unescaped, ':');
        if (!t)
                return log_syntax(unit, LOG_WARNING, filename, line, EINVAL,
                                  "Failed to parse header, name: value separator was not found, ignoring: %s", unescaped);

        *t++ = '\0';

        r = header_put(headers, TAKE_PTR(unescaped), skip_leading_chars(t, WHITESPACE));
        if (r < 0)
                return log_syntax(unit, LOG_WARNING, filename, line, r,
                                  "Failed to update headers: %s", rvalue);

        return 1;
}
