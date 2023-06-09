/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <getopt.h>
#include <sys/socket.h>
#include <unistd.h>

#include "battery-util.h"
#include "build.h"
#include "constants.h"
#include "errno-util.h"
#include "glyph-util.h"
#include "fd-util.h"
#include "log.h"
#include "main-func.h"
#include "socket-util.h"
#include "terminal-util.h"

static void help(void) {
        printf("%s\n\n"
               "Checks battery level to see whether there's enough charge.\n\n"
               "   -h --help            Show this help\n"
               "      --version         Show package version\n",
               program_invocation_short_name);
}

static void battery_check_send_plymouth_message(char *message) {
        assert(message);

        static const union sockaddr_union sa = PLYMOUTH_SOCKET;
        _cleanup_close_ int fd = -EBADF;
        size_t n = strlen(message);
        ssize_t w = n + 1;
        _cleanup_free_ char *plymouth_message = NULL;

        if (asprintf(&plymouth_message, "M\002%ld%s", w, message) < 0) {
                log_oom();
                return;
        }
        n = strlen(plymouth_message);
        w = n + 1;

        /* We set SOCK_NONBLOCK here so that we rather drop the
         * message than wait for plymouth */
        fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (fd < 0) {
                log_warning_errno(errno, "socket() failed: %m");
                return;
        }

        if (connect(fd, &sa.sa, SOCKADDR_UN_LEN(sa.un)) < 0) {
                log_full_errno(IN_SET(errno, EAGAIN, ENOENT) || ERRNO_IS_DISCONNECT(errno) ? LOG_DEBUG : LOG_WARNING, errno, "Connection to plymouth failed: %m");
                return;
        }

        if (write(fd, plymouth_message, n + 1) != w)
                log_full_errno(IN_SET(errno, EAGAIN, ENOENT) || ERRNO_IS_DISCONNECT(errno) ? LOG_DEBUG : LOG_WARNING, errno, "Failed to write to plymouth: %m");

}

static int parse_argv(int argc, char * argv[]) {

        enum {
                ARG_VERSION = 0x100,
        };

        static const struct option options[] = {
                { "help",    no_argument, NULL, 'h'         },
                { "version", no_argument, NULL, ARG_VERSION },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        return version();

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (optind < argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s takes no argument.",
                                       program_invocation_short_name);
        return 1;
}

static int run(int argc, char *argv[]) {
        int r;

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = battery_is_discharging_and_low();
        if (r < 0) {
                log_warning_errno(r, "Failed to check battery status, ignoring: %m");
                return 0;
        }
        if (r > 0) {
                _cleanup_close_ int fd = -EBADF;
                _cleanup_free_ char * message = NULL;
                log_emergency("Battery level critically low. Powering off in 10 seconds.");
                fd = open_terminal("/dev/console", O_WRONLY|O_NOCTTY|O_CLOEXEC);
                if (fd < 0)
                        log_warning_errno(fd, "Failed to open console, ignoring: %m");
                else
                        dprintf(fd, "%s" ANSI_HIGHLIGHT_RED " Battery level critically low. Powering off in 10 seconds. " ANSI_NORMAL "%s\n", special_glyph(SPECIAL_GLYPH_LOW_BATTERY), special_glyph(SPECIAL_GLYPH_LOW_BATTERY));
                if (asprintf(&message, "%s Battery level critically low. Powering off in 10 seconds.", special_glyph(SPECIAL_GLYPH_LOW_BATTERY)) < 0)
                        return log_oom();
                battery_check_send_plymouth_message(message);
                sleep(10);
        }

        return r;
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
