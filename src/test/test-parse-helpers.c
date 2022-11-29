/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/in.h>
#include <sys/socket.h>
#include <stdio.h>

#include "macro.h"
#include "parse-helpers.h"
#include "string-util.h"
#include "tests.h"

static void test_valid_item(
                const char *str,
                int expected_af,
                int expected_ip_protocol,
                uint16_t expected_nr_ports,
                uint16_t expected_port_min) {
        uint16_t nr_ports, port_min;
        int af, ip_protocol;

        assert_se(parse_socket_bind_item(str, &af, &ip_protocol, &nr_ports, &port_min) >= 0);
        assert_se(af == expected_af);
        assert_se(ip_protocol == expected_ip_protocol);
        assert_se(nr_ports == expected_nr_ports);
        assert_se(port_min == expected_port_min);

        log_info("%s: \"%s\" ok", __func__, str);
}

static void test_invalid_item(const char *str) {
        uint16_t nr_ports, port_min;
        int af, ip_protocol;

        assert_se(parse_socket_bind_item(str, &af, &ip_protocol, &nr_ports, &port_min) == -EINVAL);

        log_info("%s: \"%s\" ok", __func__, str);
}

TEST(valid_items) {
        test_valid_item("any", AF_UNSPEC, 0, 0, 0);
        test_valid_item("ipv4", AF_INET, 0, 0, 0);
        test_valid_item("ipv6", AF_INET6, 0, 0, 0);
        test_valid_item("ipv4:any", AF_INET, 0, 0, 0);
        test_valid_item("ipv6:any", AF_INET6, 0, 0, 0);
        test_valid_item("tcp", AF_UNSPEC, IPPROTO_TCP, 0, 0);
        test_valid_item("udp", AF_UNSPEC, IPPROTO_UDP, 0, 0);
        test_valid_item("tcp:any", AF_UNSPEC, IPPROTO_TCP, 0, 0);
        test_valid_item("udp:any", AF_UNSPEC, IPPROTO_UDP, 0, 0);
        test_valid_item("6666", AF_UNSPEC, 0, 1, 6666);
        test_valid_item("6666-6667", AF_UNSPEC, 0, 2, 6666);
        test_valid_item("65535", AF_UNSPEC, 0, 1, 65535);
        test_valid_item("1-65535", AF_UNSPEC, 0, 65535, 1);
        test_valid_item("ipv4:tcp", AF_INET, IPPROTO_TCP, 0, 0);
        test_valid_item("ipv4:udp", AF_INET, IPPROTO_UDP, 0, 0);
        test_valid_item("ipv6:tcp", AF_INET6, IPPROTO_TCP, 0, 0);
        test_valid_item("ipv6:udp", AF_INET6, IPPROTO_UDP, 0, 0);
        test_valid_item("ipv4:6666", AF_INET, 0, 1, 6666);
        test_valid_item("ipv6:6666", AF_INET6, 0, 1, 6666);
        test_valid_item("tcp:6666", AF_UNSPEC, IPPROTO_TCP, 1, 6666);
        test_valid_item("udp:6666", AF_UNSPEC, IPPROTO_UDP, 1, 6666);
        test_valid_item("ipv4:tcp:6666", AF_INET, IPPROTO_TCP, 1, 6666);
        test_valid_item("ipv6:tcp:6666", AF_INET6, IPPROTO_TCP, 1, 6666);
        test_valid_item("ipv6:udp:6666-6667", AF_INET6, IPPROTO_UDP, 2, 6666);
        test_valid_item("ipv6:tcp:any", AF_INET6, IPPROTO_TCP, 0, 0);
}

TEST(invalid_items) {
        test_invalid_item("");
        test_invalid_item(":");
        test_invalid_item("::");
        test_invalid_item("any:");
        test_invalid_item("meh");
        test_invalid_item("zupa:meh");
        test_invalid_item("zupa:meh:eh");
        test_invalid_item("ip");
        test_invalid_item("dccp");
        test_invalid_item("ipv6meh");
        test_invalid_item("ipv6::");
        test_invalid_item("ipv6:ipv6");
        test_invalid_item("ipv6:icmp");
        test_invalid_item("ipv6:tcp:0");
        test_invalid_item("65536");
        test_invalid_item("0-65535");
        test_invalid_item("ipv6:tcp:6666-6665");
        test_invalid_item("ipv6:tcp:6666-100000");
        test_invalid_item("ipv6::6666");
        test_invalid_item("ipv6:tcp:any:");
        test_invalid_item("ipv6:tcp:any:ipv6");
        test_invalid_item("ipv6:tcp:6666:zupa");
        test_invalid_item("ipv6:tcp:6666:any");
        test_invalid_item("ipv6:tcp:6666 zupa");
        test_invalid_item("ipv6:tcp:6666: zupa");
        test_invalid_item("ipv6:tcp:6666\n zupa");
}

TEST(open_file_parse) {
        _cleanup_(open_file_freep) OpenFile *of = NULL;
        int r;

        r = open_file_parse("/proc/1/ns/mnt:host-mount-namespace:ro", &of);

        assert_se(r == 0);
        assert_se(streq(of->path, "/proc/1/ns/mnt"));
        assert_se(streq(of->fdname, "host-mount-namespace"));
        assert_se(of->flags == OPENFILE_RDONLY);

        of = open_file_free(of);
        r = open_file_parse("/proc/1/ns/mnt", &of);

        assert_se(r == 0);
        assert_se(streq(of->path, "/proc/1/ns/mnt"));
        assert_se(streq(of->fdname, "mnt"));
        assert_se(of->flags == 0);

        of = open_file_free(of);
        r = open_file_parse("/proc/1/ns/mnt:host-mount-namespace", &of);

        assert_se(r == 0);
        assert_se(streq(of->path, "/proc/1/ns/mnt"));
        assert_se(streq(of->fdname, "host-mount-namespace"));
        assert_se(of->flags == 0);

        of = open_file_free(of);
        r = open_file_parse("/proc/1/ns/mnt::ro", &of);

        assert_se(r == 0);
        assert_se(streq(of->path, "/proc/1/ns/mnt"));
        assert_se(streq(of->fdname, "mnt"));
        assert_se(of->flags == OPENFILE_RDONLY);

        of = open_file_free(of);
        r = open_file_parse("../file.dat:file:ro", &of);

        assert_se(r == -EINVAL);

        of = open_file_free(of);
        r = open_file_parse("/proc/1/ns/mnt:host-mount-namespace:rw", &of);

        assert_se(r == -EINVAL);

        of = open_file_free(of);
        r = open_file_parse("/proc/1/ns/mnt:host-mount-namespace:append", &of);

        assert_se(r == 0);
        assert_se(streq(of->path, "/proc/1/ns/mnt"));
        assert_se(streq(of->fdname, "host-mount-namespace"));
        assert_se(of->flags == OPENFILE_APPEND);

        of = open_file_free(of);
        r = open_file_parse("/proc/1/ns/mnt:host-mount-namespace:truncate", &of);

        assert_se(r == 0);
        assert_se(streq(of->path, "/proc/1/ns/mnt"));
        assert_se(streq(of->fdname, "host-mount-namespace"));
        assert_se(of->flags == OPENFILE_TRUNC);

        of = open_file_free(of);
        r = open_file_parse("/proc/1/ns/mnt:host-mount-namespace:ro,append", &of);

        assert_se(r == -EINVAL);

        of = open_file_free(of);
        r = open_file_parse("/proc/1/ns/mnt:host-mount-namespace:ro,truncate", &of);

        assert_se(r == -EINVAL);

        of = open_file_free(of);
        r = open_file_parse("/proc/1/ns/mnt:host-mount-namespace:append,truncate", &of);

        assert_se(r == -EINVAL);

        of = open_file_free(of);
        r = open_file_parse("/proc/1/ns/mnt:host-mount-namespace:ignore", &of);

        assert_se(r == 0);
        assert_se(streq(of->path, "/proc/1/ns/mnt"));
        assert_se(streq(of->fdname, "host-mount-namespace"));
        assert_se(of->flags == OPENFILE_IGNORE);

        of = open_file_free(of);
        r = open_file_parse("/proc/1/ns/mnt:host-mount-namespace:ro,ignore", &of);

        assert_se(r == 0);
        assert_se(streq(of->path, "/proc/1/ns/mnt"));
        assert_se(streq(of->fdname, "host-mount-namespace"));
        assert_se(of->flags == (OPENFILE_RDONLY | OPENFILE_IGNORE));

        of = open_file_free(of);
        r = open_file_parse("/proc/1/ns/mnt:host-mount-namespace:ro:other", &of);

        assert_se(r == -EINVAL);
}

TEST(open_file_to_string) {
        _cleanup_free_ char *s = NULL;
        _cleanup_(open_file_freep) OpenFile *of = NULL;

        of = new0(OpenFile, 1);
        of->path = strdup("/proc/1/ns/mnt");
        of->fdname = strdup("host-mount-namespace");
        of->flags = OPENFILE_RDONLY;

        s = open_file_to_string(of);

        assert_se(streq(s, "/proc/1/ns/mnt:host-mount-namespace:ro"));

        s = mfree(s);
        of = open_file_free(of);
        of = new0(OpenFile, 1);
        of->path = strdup("/proc/1/ns/mnt");
        of->fdname = strdup("host-mount-namespace");

        s = open_file_to_string(of);

        assert_se(streq(s, "/proc/1/ns/mnt:host-mount-namespace"));

        s = mfree(s);
        of = open_file_free(of);
        of = new0(OpenFile, 1);
        of->path = strdup("/proc/1/ns/mnt");
        of->fdname = strdup("mnt");
        of->flags = OPENFILE_RDONLY;

        s = open_file_to_string(of);

        assert_se(streq(s, "/proc/1/ns/mnt::ro"));

        s = mfree(s);
        of = open_file_free(of);
        of = new0(OpenFile, 1);
        of->path = strdup("/path:with:colon");
        of->fdname = strdup("path:with:colon");

        s = open_file_to_string(of);

        assert_se(streq(s, "/path\\:with\\:colon"));

        s = mfree(s);
        of = open_file_free(of);
        of = new0(OpenFile, 1);
        of->path = strdup("/proc/1/ns/mnt");
        of->fdname = strdup("host-mount-namespace");
        of->flags = OPENFILE_APPEND;

        s = open_file_to_string(of);

        assert_se(streq(s, "/proc/1/ns/mnt:host-mount-namespace:append"));

        s = mfree(s);
        of = open_file_free(of);
        of = new0(OpenFile, 1);
        of->path = strdup("/proc/1/ns/mnt");
        of->fdname = strdup("host-mount-namespace");
        of->flags = OPENFILE_TRUNC;

        s = open_file_to_string(of);

        assert_se(streq(s, "/proc/1/ns/mnt:host-mount-namespace:truncate"));

        s = mfree(s);
        of = open_file_free(of);
        of = new0(OpenFile, 1);
        of->path = strdup("/proc/1/ns/mnt");
        of->fdname = strdup("host-mount-namespace");
        of->flags = OPENFILE_IGNORE;

        s = open_file_to_string(of);

        assert_se(streq(s, "/proc/1/ns/mnt:host-mount-namespace:ignore"));

        s = mfree(s);
        of = open_file_free(of);
        of = new0(OpenFile, 1);
        of->path = strdup("/proc/1/ns/mnt");
        of->fdname = strdup("host-mount-namespace");
        of->flags = OPENFILE_RDONLY | OPENFILE_IGNORE;

        s = open_file_to_string(of);

        assert_se(streq(s, "/proc/1/ns/mnt:host-mount-namespace:ro,ignore"));
}

DEFINE_TEST_MAIN(LOG_INFO);
