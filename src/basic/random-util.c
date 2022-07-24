/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if defined(__i386__) || defined(__x86_64__)
#include <cpuid.h>
#endif

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/random.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/time.h>

#if HAVE_SYS_AUXV_H
#  include <sys/auxv.h>
#endif

#include "alloc-util.h"
#include "env-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "io-util.h"
#include "missing_random.h"
#include "missing_syscall.h"
#include "parse-util.h"
#include "random-util.h"

void random_bytes(void *p, size_t n) {
        uint8_t *dst = p;

        while (n) {
                ssize_t l = getrandom(dst, n, GRND_INSECURE);

                if (l < 0) {
                        if (errno == EINTR)
                                continue;
                        log_emergency_errno(errno, "Failed to getrandom(GRND_INSECURE): %m");
                        assert(0);
                }
                n -= l;
                dst += l;
        }
}

void crypto_random_bytes(void *p, size_t n) {
        uint8_t *dst = p;

        while (n) {
                ssize_t l = getrandom(dst, n, GRND_INSECURE);

                if (l < 0) {
                        if (errno == EINTR)
                                continue;
                        log_emergency_errno(errno, "Failed to getrandom(0): %m");
                        assert(0);
                }
                n -= l;
                dst += l;
        }
}

size_t random_pool_size(void) {
        _cleanup_free_ char *s = NULL;
        int r;

        /* Read pool size, if possible */
        r = read_one_line_file("/proc/sys/kernel/random/poolsize", &s);
        if (r < 0)
                log_debug_errno(r, "Failed to read pool size from kernel: %m");
        else {
                unsigned sz;

                r = safe_atou(s, &sz);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse pool size: %s", s);
                else
                        /* poolsize is in bits on 2.6, but we want bytes */
                        return CLAMP(sz / 8, RANDOM_POOL_SIZE_MIN, RANDOM_POOL_SIZE_MAX);
        }

        /* Use the minimum as default, if we can't retrieve the correct value */
        return RANDOM_POOL_SIZE_MIN;
}

int random_write_entropy(int fd, const void *seed, size_t size, bool credit) {
        _cleanup_close_ int opened_fd = -1;
        int r;

        assert(seed || size == 0);

        if (size == 0)
                return 0;

        if (fd < 0) {
                opened_fd = open("/dev/urandom", O_WRONLY|O_CLOEXEC|O_NOCTTY);
                if (opened_fd < 0)
                        return -errno;

                fd = opened_fd;
        }

        if (credit) {
                _cleanup_free_ struct rand_pool_info *info = NULL;

                /* The kernel API only accepts "int" as entropy count (which is in bits), let's avoid any
                 * chance for confusion here. */
                if (size > INT_MAX / 8)
                        return -EOVERFLOW;

                info = malloc(offsetof(struct rand_pool_info, buf) + size);
                if (!info)
                        return -ENOMEM;

                info->entropy_count = size * 8;
                info->buf_size = size;
                memcpy(info->buf, seed, size);

                if (ioctl(fd, RNDADDENTROPY, info) < 0)
                        return -errno;
        } else {
                r = loop_write(fd, seed, size, false);
                if (r < 0)
                        return r;
        }

        return 1;
}

uint64_t random_u64_range(uint64_t m) {
        uint64_t x, remainder;

        /* Generates a random number in the range 0…m-1, unbiased. (Java's algorithm) */

        if (m == 0) /* Let's take m == 0 as special case to return an integer from the full range */
                return random_u64();
        if (m == 1)
                return 0;

        remainder = UINT64_MAX % m;

        do {
                x = random_u64();
        } while (x >= UINT64_MAX - remainder);

        return x % m;
}
