# New Fuzz Harness Templates for systemd

These are skeleton harnesses for the 16 gap coverage targets identified in Section B
of the task list. Each follows the existing systemd fuzz harness pattern using
`LLVMFuzzerTestOneInput` compatible with both libFuzzer and the regression test
driver in `src/fuzz/fuzz-main.c`.

---

## B1. fuzz-dnssec-verify.c

```c
/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-packet.h"
#include "resolved-dns-dnssec.h"
#include "fuzz.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;

        if (size < 12)  /* Minimum DNS header */
                return 0;

        if (dns_packet_new(&p, DNS_PROTOCOL_DNS, 0, size) < 0)
                return 0;

        memcpy(DNS_PACKET_DATA(p), data, size);
        p->size = size;

        (void) dns_packet_extract(p);

        if (p->answer) {
                DnsResourceRecord *rrsig = NULL;
                DNS_ANSWER_FOREACH(rrsig, p->answer) {
                        if (rrsig->key->type == DNS_TYPE_RRSIG)
                                (void) dnssec_verify_rrset(p->answer, rrsig->rrsig.key_tag,
                                                          rrsig, USEC_INFINITY, NULL);
                }
        }

        return 0;
}
```

## B2. fuzz-user-record.c

```c
/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"
#include "user-record.h"
#include "fuzz.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_(user_record_unrefp) UserRecord *ur = NULL;

        if (sd_json_parse(data, size, 0, &v, NULL) < 0)
                return 0;

        (void) user_record_new();
        (void) user_record_load(v, USER_RECORD_LOAD_FULL|USER_RECORD_PERMISSIVE, &ur);

        return 0;
}
```

## B3. fuzz-group-record.c

```c
/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"
#include "group-record.h"
#include "fuzz.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_(group_record_unrefp) GroupRecord *gr = NULL;

        if (sd_json_parse(data, size, 0, &v, NULL) < 0)
                return 0;

        (void) group_record_load(v, USER_RECORD_LOAD_FULL|USER_RECORD_PERMISSIVE, &gr);

        return 0;
}
```

## B4. fuzz-credential.c

```c
/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "creds-util.h"
#include "iovec-util.h"
#include "fuzz.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(iovec_done) struct iovec ret = {};

        /* Try decrypting arbitrary credential blobs - should fail gracefully */
        (void) decrypt_credential_and_warn(
                        "fuzz",
                        /* validate_timestamp= */ USEC_INFINITY,
                        /* tpm2_device= */ NULL,
                        /* tpm2_signature_path= */ NULL,
                        &IOVEC_MAKE((uint8_t*) data, size),
                        CREDENTIAL_ANY_SCOPE,
                        &ret);

        return 0;
}
```

## B5. fuzz-dissect-image.c

```c
/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* NOTE: This harness requires careful sandboxing since dissect_image
 * attempts to set up loop devices. For pure fuzzing, target the GPT
 * partition table parser directly instead. */

#include "dissect-image.h"
#include "fuzz.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        /* Focus on GPT header/entry parsing without requiring block devices.
         * The actual dissect_image_file() is too heavy for fuzzing.
         * Instead, exercise the partition discovery logic. */

        if (size < 512)  /* Minimum GPT header */
                return 0;

        /* Parse GPT protective MBR + header */
        /* TODO: Extract partition table parsing into standalone function */

        return 0;
}
```

## B6. fuzz-conf-parser.c

```c
/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "conf-parser.h"
#include "fd-util.h"
#include "fuzz.h"
#include "tmpfile-util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *p = NULL;

        f = data_to_tmpfile(data, size);
        if (!f)
                return 0;

        /* Parse with a minimal config table - exercises the generic parser */
        static const ConfigTableItem items[] = {
                { "Section", "Key",     config_parse_string,  0, NULL },
                { "Section", "Bool",    config_parse_bool,    0, NULL },
                { "Section", "Unsigned", config_parse_unsigned, 0, NULL },
                {}
        };

        (void) config_parse(
                        NULL, /* unit */
                        "fuzz", /* filename */
                        f,
                        "Section\0",
                        config_item_table_lookup,
                        items,
                        CONFIG_PARSE_WARN,
                        NULL, /* userdata */
                        NULL);

        return 0;
}
```

## B7. fuzz-seccomp-parse.c

```c
/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "seccomp-util.h"
#include "fuzz.h"
#include "set.h"
#include "string-util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_free_ char *s = NULL;
        _cleanup_set_free_ Set *filter = NULL;

        s = memdup_suffix0(data, size);
        if (!s)
                return 0;

        /* Exercise syscall filter string parsing */
        (void) seccomp_parse_syscall_filter(s, -1, &filter, SECCOMP_PARSE_PERMISSIVE, NULL, NULL, 0);

        return 0;
}
```

## B8. fuzz-escape.c

```c
/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "escape.h"
#include "fuzz.h"
#include "string-util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_free_ char *unescaped = NULL, *escaped = NULL;

        /* Test C-style unescaping */
        (void) cunescape_length((const char*) data, size, 0, &unescaped);

        /* Test with different unescape flags */
        free(unescaped);
        unescaped = NULL;
        (void) cunescape_length((const char*) data, size,
                                UNESCAPE_RELAX | UNESCAPE_ACCEPT_NUL, &unescaped);

        /* Test shell escaping roundtrip */
        _cleanup_free_ char *s = memdup_suffix0(data, size);
        if (s) {
                escaped = shell_escape(s, "\"");
                free(escaped);
                escaped = shell_maybe_quote(s, 0);
        }

        return 0;
}
```

## B9. fuzz-hw-addr.c

```c
/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "ether-addr-util.h"
#include "fuzz.h"
#include "string-util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_free_ char *s = NULL;
        struct hw_addr_data hw = {};
        struct ether_addr ether = {};

        s = memdup_suffix0(data, size);
        if (!s)
                return 0;

        (void) parse_hw_addr(s, &hw);
        (void) parse_hw_addr_full(s, SIZE_MAX, &hw);
        (void) parse_ether_addr(s, &ether);

        return 0;
}
```

## B10. fuzz-socket-addr.c

```c
/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "socket-util.h"
#include "fuzz.h"
#include "string-util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_free_ char *s = NULL;
        SocketAddress sa = {};

        s = memdup_suffix0(data, size);
        if (!s)
                return 0;

        (void) socket_address_parse(&sa, s);

        /* Also test Unix socket address parsing */
        memset(&sa, 0, sizeof(sa));
        (void) socket_address_parse_unix(&sa, s);

        return 0;
}
```

## B11. fuzz-device-db.c

```c
/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "device-private.h"
#include "fuzz.h"
#include "tmpfile-util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *path = NULL;

        f = data_to_tmpfile(data, size);
        if (!f)
                return 0;

        /* Create a minimal device to read DB into */
        if (sd_device_new_from_syspath(&dev, "/sys/class/net/lo") < 0)
                return 0;

        /* Exercise the DB reader with arbitrary content */
        (void) device_read_db_internal_filename(dev, "/dev/null");

        return 0;
}
```

## B12. fuzz-netlink-message.c

```c
/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "netlink-internal.h"
#include "fuzz.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;

        if (size < sizeof(struct nlmsghdr))
                return 0;

        /* Validate netlink message header and attributes */
        const struct nlmsghdr *nlh = (const struct nlmsghdr*) data;
        if (nlh->nlmsg_len > size)
                return 0;

        /* TODO: Create message from raw bytes and exercise attribute parsing */

        return 0;
}
```

## B13. fuzz-qcow2.c

```c
/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* NOTE: Requires src/import/ to be built */

#include "fuzz.h"
#include "fd-util.h"
#include "tmpfile-util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_close_ int fd = -EBADF;

        if (size < 72)  /* Minimum QCOW2 header */
                return 0;

        /* Verify QCOW2 magic */
        if (memcmp(data, "QFI\xfb", 4) != 0)
                return 0;

        /* TODO: Exercise qcow2 header parsing and L1/L2 table validation */

        return 0;
}
```

## B14. fuzz-tmpfiles.c

```c
/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fuzz.h"
#include "tmpfile-util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_fclose_ FILE *f = NULL;

        f = data_to_tmpfile(data, size);
        if (!f)
                return 0;

        /* TODO: Exercise tmpfiles.d line parser in dry-run mode
         * This needs the parser to be factored out of main() */

        return 0;
}
```

## B15. fuzz-sysusers.c

```c
/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fuzz.h"
#include "tmpfile-util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_fclose_ FILE *f = NULL;

        f = data_to_tmpfile(data, size);
        if (!f)
                return 0;

        /* TODO: Exercise sysusers.d line parser in dry-run mode
         * This needs the parser to be factored out of main() */

        return 0;
}
```

## B16. fuzz-recovery-key.c

```c
/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "recovery-key.h"
#include "fuzz.h"
#include "string-util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_free_ char *s = NULL, *normalized = NULL;

        s = memdup_suffix0(data, size);
        if (!s)
                return 0;

        (void) normalize_recovery_key(s, &normalized);

        return 0;
}
```

---

## Build Integration

Add to `src/fuzz/meson.build`:

```meson
# Section B: New fuzz targets
fuzz_tests += [
  fuzz_template + {
    'sources': files('fuzz-dnssec-verify.c'),
    'dependencies': [libshared, libsystemd_resolve_core],
  },
  fuzz_template + {
    'sources': files('fuzz-user-record.c'),
    'dependencies': [libshared],
  },
  fuzz_template + {
    'sources': files('fuzz-group-record.c'),
    'dependencies': [libshared],
  },
  # ... etc
]
```

For OSS-Fuzz integration, add target names to `tools/oss-fuzz.sh`.
