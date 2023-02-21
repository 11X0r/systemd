/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stddef.h>

#include "log.h"
#include "macro.h"
#include "bitfield.h"
#include "tests.h"

TEST(saturate_add) {
        assert_se(saturate_add(1, 2, UINT8_MAX) == 3);
        assert_se(saturate_add(1, UINT8_MAX-2, UINT8_MAX) == UINT8_MAX-1);
        assert_se(saturate_add(1, UINT8_MAX-1, UINT8_MAX) == UINT8_MAX);
        assert_se(saturate_add(1, UINT8_MAX, UINT8_MAX) == UINT8_MAX);
        assert_se(saturate_add(2, UINT8_MAX, UINT8_MAX) == UINT8_MAX);
        assert_se(saturate_add(60, 60, 50) == 50);
}

TEST(align_power2) {
        unsigned long i, p2;

        assert_se(ALIGN_POWER2(0) == 0);
        assert_se(ALIGN_POWER2(1) == 1);
        assert_se(ALIGN_POWER2(2) == 2);
        assert_se(ALIGN_POWER2(3) == 4);
        assert_se(ALIGN_POWER2(4) == 4);
        assert_se(ALIGN_POWER2(5) == 8);
        assert_se(ALIGN_POWER2(6) == 8);
        assert_se(ALIGN_POWER2(7) == 8);
        assert_se(ALIGN_POWER2(9) == 16);
        assert_se(ALIGN_POWER2(10) == 16);
        assert_se(ALIGN_POWER2(11) == 16);
        assert_se(ALIGN_POWER2(12) == 16);
        assert_se(ALIGN_POWER2(13) == 16);
        assert_se(ALIGN_POWER2(14) == 16);
        assert_se(ALIGN_POWER2(15) == 16);
        assert_se(ALIGN_POWER2(16) == 16);
        assert_se(ALIGN_POWER2(17) == 32);

        assert_se(ALIGN_POWER2(ULONG_MAX) == 0);
        assert_se(ALIGN_POWER2(ULONG_MAX - 1) == 0);
        assert_se(ALIGN_POWER2(ULONG_MAX - 1024) == 0);
        assert_se(ALIGN_POWER2(ULONG_MAX / 2) == ULONG_MAX / 2 + 1);
        assert_se(ALIGN_POWER2(ULONG_MAX + 1) == 0);

        for (i = 1; i < 131071; ++i) {
                for (p2 = 1; p2 < i; p2 <<= 1)
                        /* empty */ ;

                assert_se(ALIGN_POWER2(i) == p2);
        }

        for (i = ULONG_MAX - 1024; i < ULONG_MAX; ++i) {
                for (p2 = 1; p2 && p2 < i; p2 <<= 1)
                        /* empty */ ;

                assert_se(ALIGN_POWER2(i) == p2);
        }
}

TEST(max) {
        static const struct {
                int a;
                int b[CONST_MAX(10, 100)];
        } val1 = {
                .a = CONST_MAX(10, 100),
        };
        int d = 0;
        unsigned long x = 12345;
        unsigned long y = 54321;
        const char str[] = "a_string_constant";
        const unsigned long long arr[] = {9999ULL, 10ULL, 0ULL, 3000ULL, 2000ULL, 1000ULL, 100ULL, 9999999ULL};
        void *p = (void *)str;
        void *q = (void *)&str[16];

        assert_cc(sizeof(val1.b) == sizeof(int) * 100);

        /* CONST_MAX returns (void) instead of a value if the passed arguments
         * are not of the same type or not constant expressions. */
        assert_cc(__builtin_types_compatible_p(typeof(CONST_MAX(1, 10)), int));
        assert_cc(__builtin_types_compatible_p(typeof(CONST_MAX(1, 1U)), void));

        assert_se(val1.a == 100);
        assert_se(MAX(++d, 0) == 1);
        assert_se(d == 1);

        assert_cc(MAXSIZE(char[3], uint16_t) == 3);
        assert_cc(MAXSIZE(char[3], uint32_t) == 4);
        assert_cc(MAXSIZE(char, long) == sizeof(long));

        assert_se(MAX(-5, 5) == 5);
        assert_se(MAX(5, 5) == 5);
        assert_se(MAX(MAX(1, MAX(2, MAX(3, 4))), 5) == 5);
        assert_se(MAX(MAX(1, MAX(2, MAX(3, 2))), 1) == 3);
        assert_se(MAX(MIN(1, MIN(2, MIN(3, 4))), 5) == 5);
        assert_se(MAX(MAX(1, MIN(2, MIN(3, 2))), 1) == 2);
        assert_se(LESS_BY(8, 4) == 4);
        assert_se(LESS_BY(8, 8) == 0);
        assert_se(LESS_BY(4, 8) == 0);
        assert_se(LESS_BY(16, LESS_BY(8, 4)) == 12);
        assert_se(LESS_BY(4, LESS_BY(8, 4)) == 0);
        assert_se(CMP(3, 5) == -1);
        assert_se(CMP(5, 3) == 1);
        assert_se(CMP(5, 5) == 0);
        assert_se(CMP(x, y) == -1);
        assert_se(CMP(y, x) == 1);
        assert_se(CMP(x, x) == 0);
        assert_se(CMP(y, y) == 0);
        assert_se(CMP(UINT64_MAX, (uint64_t) 0) == 1);
        assert_se(CMP((uint64_t) 0, UINT64_MAX) == -1);
        assert_se(CMP(UINT64_MAX, UINT64_MAX) == 0);
        assert_se(CMP(INT64_MIN, INT64_MAX) == -1);
        assert_se(CMP(INT64_MAX, INT64_MIN) == 1);
        assert_se(CMP(INT64_MAX, INT64_MAX) == 0);
        assert_se(CMP(INT64_MIN, INT64_MIN) == 0);
        assert_se(CMP(INT64_MAX, (int64_t) 0) == 1);
        assert_se(CMP((int64_t) 0, INT64_MIN) == 1);
        assert_se(CMP(INT64_MIN, (int64_t) 0) == -1);
        assert_se(CMP((int64_t) 0, INT64_MAX) == -1);
        assert_se(CMP(&str[2], &str[7]) == -1);
        assert_se(CMP(&str[2], &str[2]) == 0);
        assert_se(CMP(&str[7], (const char *)str) == 1);
        assert_se(CMP(str[2], str[7]) == 1);
        assert_se(CMP(str[7], *str) == 1);
        assert_se(CMP((const unsigned long long *)arr, &arr[3]) == -1);
        assert_se(CMP(*arr, arr[3]) == 1);
        assert_se(CMP(p, q) == -1);
        assert_se(CMP(q, p) == 1);
        assert_se(CMP(p, p) == 0);
        assert_se(CMP(q, q) == 0);
        assert_se(CLAMP(-5, 0, 1) == 0);
        assert_se(CLAMP(5, 0, 1) == 1);
        assert_se(CLAMP(5, -10, 1) == 1);
        assert_se(CLAMP(5, -10, 10) == 5);
        assert_se(CLAMP(CLAMP(0, -10, 10), CLAMP(-5, 10, 20), CLAMP(100, -5, 20)) == 10);
}

#pragma GCC diagnostic push
#ifdef __clang__
#  pragma GCC diagnostic ignored "-Waddress-of-packed-member"
#endif

TEST(container_of) {
        struct mytype {
                uint8_t pad1[3];
                uint64_t v1;
                uint8_t pad2[2];
                uint32_t v2;
        } myval = { };

        assert_cc(sizeof(myval) >= 17);
        assert_se(container_of(&myval.v1, struct mytype, v1) == &myval);
        assert_se(container_of(&myval.v2, struct mytype, v2) == &myval);
        assert_se(container_of(&container_of(&myval.v2,
                                             struct mytype,
                                             v2)->v1,
                               struct mytype,
                               v1) == &myval);
}

#pragma GCC diagnostic pop

TEST(div_round_up) {
        int div;

        /* basic tests */
        assert_se(DIV_ROUND_UP(0, 8) == 0);
        assert_se(DIV_ROUND_UP(1, 8) == 1);
        assert_se(DIV_ROUND_UP(8, 8) == 1);
        assert_se(DIV_ROUND_UP(12, 8) == 2);
        assert_se(DIV_ROUND_UP(16, 8) == 2);

        /* test multiple evaluation */
        div = 0;
        assert_se(DIV_ROUND_UP(div++, 8) == 0 && div == 1);
        assert_se(DIV_ROUND_UP(++div, 8) == 1 && div == 2);
        assert_se(DIV_ROUND_UP(8, div++) == 4 && div == 3);
        assert_se(DIV_ROUND_UP(8, ++div) == 2 && div == 4);

        /* overflow test with exact division */
        assert_se(sizeof(0U) == 4);
        assert_se(0xfffffffaU % 10U == 0U);
        assert_se(0xfffffffaU / 10U == 429496729U);
        assert_se(DIV_ROUND_UP(0xfffffffaU, 10U) == 429496729U);
        assert_se((0xfffffffaU + 10U - 1U) / 10U == 0U);
        assert_se(0xfffffffaU / 10U + !!(0xfffffffaU % 10U) == 429496729U);

        /* overflow test with rounded division */
        assert_se(0xfffffffdU % 10U == 3U);
        assert_se(0xfffffffdU / 10U == 429496729U);
        assert_se(DIV_ROUND_UP(0xfffffffdU, 10U) == 429496730U);
        assert_se((0xfffffffdU + 10U - 1U) / 10U == 0U);
        assert_se(0xfffffffdU / 10U + !!(0xfffffffdU % 10U) == 429496730U);
}

TEST(ptr_to_int) {
        /* Primary reason to have this test is to validate that pointers are large enough to hold entire int range */
        assert_se(PTR_TO_INT(INT_TO_PTR(0)) == 0);
        assert_se(PTR_TO_INT(INT_TO_PTR(1)) == 1);
        assert_se(PTR_TO_INT(INT_TO_PTR(-1)) == -1);
        assert_se(PTR_TO_INT(INT_TO_PTR(INT_MAX)) == INT_MAX);
        assert_se(PTR_TO_INT(INT_TO_PTR(INT_MIN)) == INT_MIN);
}

TEST(in_set) {
        assert_se(IN_SET(1, 1, 2));
        assert_se(IN_SET(1, 1, 2, 3, 4));
        assert_se(IN_SET(2, 1, 2, 3, 4));
        assert_se(IN_SET(3, 1, 2, 3, 4));
        assert_se(IN_SET(4, 1, 2, 3, 4));
        assert_se(!IN_SET(0, 1, 2));
        assert_se(!IN_SET(0, 1, 2, 3, 4));

        struct {
                unsigned x:3;
        } t = { 1 };

        assert_se(IN_SET(t.x, 1, 2));
        assert_se(IN_SET(t.x, 1, 2, 3, 4));
        assert_se(IN_SET(t.x, 2, 3, 4, 1));
        assert_se(!IN_SET(t.x, 0, 2));
        assert_se(!IN_SET(t.x, 2, 3, 4));
}

TEST(foreach_pointer) {
        int a, b, c, *i;
        size_t k = 0;

        FOREACH_POINTER(i, &a, &b, &c) {
                switch (k) {

                case 0:
                        assert_se(i == &a);
                        break;

                case 1:
                        assert_se(i == &b);
                        break;

                case 2:
                        assert_se(i == &c);
                        break;

                default:
                        assert_not_reached();
                        break;
                }

                k++;
        }

        assert_se(k == 3);

        FOREACH_POINTER(i, &b) {
                assert_se(k == 3);
                assert_se(i == &b);
                k = 4;
        }

        assert_se(k == 4);

        FOREACH_POINTER(i, NULL, &c, NULL, &b, NULL, &a, NULL) {
                switch (k) {

                case 4:
                        assert_se(i == NULL);
                        break;

                case 5:
                        assert_se(i == &c);
                        break;

                case 6:
                        assert_se(i == NULL);
                        break;

                case 7:
                        assert_se(i == &b);
                        break;

                case 8:
                        assert_se(i == NULL);
                        break;

                case 9:
                        assert_se(i == &a);
                        break;

                case 10:
                        assert_se(i == NULL);
                        break;

                default:
                        assert_not_reached();
                        break;
                }

                k++;
        }

        assert_se(k == 11);
}

TEST(align_to) {
        assert_se(ALIGN_TO(0, 1) == 0);
        assert_se(ALIGN_TO(1, 1) == 1);
        assert_se(ALIGN_TO(2, 1) == 2);
        assert_se(ALIGN_TO(3, 1) == 3);
        assert_se(ALIGN_TO(4, 1) == 4);
        assert_se(ALIGN_TO(SIZE_MAX-1, 1) == SIZE_MAX-1);
        assert_se(ALIGN_TO(SIZE_MAX, 1) == SIZE_MAX);

        assert_se(ALIGN_TO(0, 2) == 0);
        assert_se(ALIGN_TO(1, 2) == 2);
        assert_se(ALIGN_TO(2, 2) == 2);
        assert_se(ALIGN_TO(3, 2) == 4);
        assert_se(ALIGN_TO(4, 2) == 4);
        assert_se(ALIGN_TO(SIZE_MAX-3, 2) == SIZE_MAX-3);
        assert_se(ALIGN_TO(SIZE_MAX-2, 2) == SIZE_MAX-1);
        assert_se(ALIGN_TO(SIZE_MAX-1, 2) == SIZE_MAX-1);
        assert_se(ALIGN_TO(SIZE_MAX, 2) == SIZE_MAX); /* overflow */

        assert_se(ALIGN_TO(0, 4) == 0);
        assert_se(ALIGN_TO(1, 4) == 4);
        assert_se(ALIGN_TO(2, 4) == 4);
        assert_se(ALIGN_TO(3, 4) == 4);
        assert_se(ALIGN_TO(4, 4) == 4);
        assert_se(ALIGN_TO(SIZE_MAX-3, 4) == SIZE_MAX-3);
        assert_se(ALIGN_TO(SIZE_MAX-2, 4) == SIZE_MAX); /* overflow */
        assert_se(ALIGN_TO(SIZE_MAX-1, 4) == SIZE_MAX); /* overflow */
        assert_se(ALIGN_TO(SIZE_MAX, 4) == SIZE_MAX);   /* overflow */

        assert_cc(CONST_ALIGN_TO(96, 512) == 512);
        assert_cc(CONST_ALIGN_TO(511, 512) == 512);
        assert_cc(CONST_ALIGN_TO(512, 512) == 512);
        assert_cc(CONST_ALIGN_TO(513, 512) == 1024);
        assert_cc(CONST_ALIGN_TO(sizeof(int), 64) == 64);

        assert_cc(__builtin_types_compatible_p(typeof(CONST_ALIGN_TO(4, 3)), void));
        assert_cc(__builtin_types_compatible_p(typeof(CONST_ALIGN_TO(SIZE_MAX, 512)), void));
}

TEST(flags) {
        enum {
                F1 = 1 << 0,
                F2 = 1 << 1,
                F3 = 1 << 2,
                F_ALL = F1 | F2 | F3
        };
        unsigned n, f;

        assert_se(FLAGS_SET(0, 0));
        assert_se(FLAGS_SET(F1, F1));
        assert_se(FLAGS_SET(F1 | F2, F1));
        assert_se(FLAGS_SET(F1 | F3, F1 | F3));
        assert_se(FLAGS_SET(F1 | F2 | F3, F_ALL));
        assert_se(!FLAGS_SET(0, F1));
        assert_se(!FLAGS_SET(F2, F1));
        assert_se(!FLAGS_SET(F1 | F2, F3));
        assert_se(!FLAGS_SET(F1 | F2, F1 | F3));
        assert_se(!FLAGS_SET(F1 | F2 | F3, ~F_ALL));

        /* Check for no double eval. */
        n = F2;
        f = F1;
        assert_se(!FLAGS_SET(--n, ++f));
        assert_se(n == F1);
        assert_se(f == F2);

        SET_FLAG(n, F3, true);
        assert_se(n == (F1 | F3));
        SET_FLAG(n, F2, false);
        assert_se(n == (F1 | F3));
        SET_FLAG(n, F3, false);
        assert_se(n == F1);
        SET_FLAG(n, F1, true);
        assert_se(n == F1);
        SET_FLAG(n, F1 | F3, true);
        assert_se(n == (F1 | F3));
        SET_FLAG(n, F_ALL, false);
        assert_se(n == 0);

        assert_se(UPDATE_FLAG(0, 0, true) == 0);
        assert_se(UPDATE_FLAG(0, F1, true) == F1);
        assert_se(UPDATE_FLAG(0, F1 | F2, true) == (F1 | F2));
        assert_se(UPDATE_FLAG(F1, 0, true) == F1);
        assert_se(UPDATE_FLAG(F1, F1, true) == F1);
        assert_se(UPDATE_FLAG(F1, F3, true) == (F1 | F3));
        assert_se(UPDATE_FLAG(F1, F1 | F3, true) == (F1 | F3));
        assert_se(UPDATE_FLAG(F1, F_ALL, true) == F_ALL);
        assert_se(UPDATE_FLAG(0, 0, false) == 0);
        assert_se(UPDATE_FLAG(0, F1, false) == 0);
        assert_se(UPDATE_FLAG(0, F1 | F2, false) == 0);
        assert_se(UPDATE_FLAG(F1, 0, false) == F1);
        assert_se(UPDATE_FLAG(F1, F1, false) == 0);
        assert_se(UPDATE_FLAG(F1, F3, false) == F1);
        assert_se(UPDATE_FLAG(F1, F1 | F3, false) == 0);
        assert_se(UPDATE_FLAG(F1, F2 | F3, false) == F1);
        assert_se(UPDATE_FLAG(F1, F_ALL, false) == 0);
        assert_se(UPDATE_FLAG(F_ALL, F_ALL, false) == 0);

        /* Check for no double eval. */
        n = F2;
        f = F1;
        assert_se(UPDATE_FLAG(--n, ++f, true) == (F1 | F2));
        assert_se(n == F1);
        assert_se(f == F2);
}

#define __TEST_BITS(func, bits, _indexes_, _i_, ...)                    \
        ({                                                              \
                unsigned _i_;                                           \
                VA_ARGS_FOREACH(_i_, ##__VA_ARGS__)                     \
                        assert_se(func((bits), _i_));                   \
        })
#define _TEST_BITS(func, bits, ...) __TEST_BITS(func, bits, UNIQ_T(_indexes_, UNIQ), UNIQ_T(_i_, UNIQ), ##__VA_ARGS__)
#define TEST_BITS_SET(bits, ...)                                        \
        do {                                                            \
                assert_se(BITS_SET(bits, ##__VA_ARGS__));               \
                _TEST_BITS(BITS_SET, bits, ##__VA_ARGS__);              \
        } while (0)
#define TEST_BITS_CLEAR(bits, ...) _TEST_BITS(!BITS_SET, bits, ##__VA_ARGS__)

TEST(bits) {
        int count;

        /* Test uint8_t */
        TEST_BITS_SET(0x81, 0, 7);
        TEST_BITS_CLEAR(0x81, 1, 2, 3, 4, 5, 6);
        uint8_t expected8 = 0;
        BIT_FOREACH(i, 0x81)
                expected8 |= UINT8_C(1) << i;
        assert_se(expected8 == 0x81);
        uint8_t u8 = 0x91;
        TEST_BITS_SET(u8, 0, 4, 7);
        TEST_BITS_CLEAR(u8, 1, 2, 3, 5, 6);
        SET_BIT(u8, 1);
        TEST_BITS_SET(u8, 0, 1, 4, 7);
        TEST_BITS_CLEAR(u8, 2, 3, 5, 6);
        SET_BIT(u8, 3, 5);
        TEST_BITS_SET(u8, 0, 1, 3, 4, 5, 7);
        TEST_BITS_CLEAR(u8, 2, 6);
        CLEAR_BIT(u8, 4);
        TEST_BITS_SET(u8, 0, 1, 3, 5, 7);
        TEST_BITS_CLEAR(u8, 2, 4, 6);
        CLEAR_BIT(u8, 0, 1, 7);
        TEST_BITS_SET(u8, 3, 5);
        TEST_BITS_CLEAR(u8, 0, 1, 2, 4, 6, 7);
        expected8 = 0;
        BIT_FOREACH(i, u8)
                expected8 |= UINT8_C(1) << i;
        assert_se(expected8 == u8);
        u8 = 0;
        TEST_BITS_CLEAR(u8, 0, 1, 2, 3, 4, 5, 6, 7);
        BIT_FOREACH(i, u8)
                assert_se(0);
        u8 = ~u8;
        TEST_BITS_SET(u8, 0, 1, 2, 3, 4, 5, 6, 7);
        count = 0;
        BIT_FOREACH(i, u8)
                count++;
        assert_se(count == 8);

        /* Test uint16_t */
        TEST_BITS_SET(0x1f81, 0, 7, 8, 9, 10, 11, 12);
        TEST_BITS_CLEAR(0x1f81, 1, 2, 3, 4, 5, 6, 13, 14, 15);
        uint16_t expected16 = 0;
        BIT_FOREACH(i, 0x1f81)
                expected16 |= UINT16_C(1) << i;
        assert_se(expected16 == 0x1f81);
        uint16_t u16 = 0xf060;
        TEST_BITS_SET(u16, 5, 6, 12, 13, 14, 15);
        TEST_BITS_CLEAR(u16, 0, 1, 2, 3, 4, 7, 8, 9, 10, 11);
        SET_BIT(u16, 1, 8);
        TEST_BITS_SET(u16, 1, 5, 6, 8, 12, 13, 14, 15);
        TEST_BITS_CLEAR(u16, 0, 2, 3, 4, 7, 9, 10, 11);
        CLEAR_BIT(u16, 13, 14);
        TEST_BITS_SET(u16, 1, 5, 6, 8, 12, 15);
        TEST_BITS_CLEAR(u16, 0, 2, 3, 4, 7, 9, 10, 11, 13, 14);
        expected16 = 0;
        BIT_FOREACH(i, u16)
                expected16 |= UINT16_C(1) << i;
        assert_se(expected16 == u16);
        u16 = 0;
        TEST_BITS_CLEAR(u16, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
        BIT_FOREACH(i, u16)
                assert_se(0);
        u16 = ~u16;
        TEST_BITS_SET(u16, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
        count = 0;
        BIT_FOREACH(i, u16)
                count++;
        assert_se(count == 16);

        /* Test uint32_t */
        TEST_BITS_SET(0x80224f10, 4, 8, 9, 10, 11, 14, 17, 21, 31);
        TEST_BITS_CLEAR(0x80224f10, 0, 1, 2, 3, 5, 6, 7, 12, 13, 15, 16, 18, 19, 20, 22, 23, 24, 25, 26, 27, 28, 29, 30);
        uint32_t expected32 = 0;
        BIT_FOREACH(i, 0x80224f10)
                expected32 |= UINT32_C(1) << i;
        assert_se(expected32 == 0x80224f10);
        uint32_t u32 = 0x605e0388;
        TEST_BITS_SET(u32, 3, 7, 8, 9, 17, 18, 19, 20, 22, 29, 30);
        TEST_BITS_CLEAR(u32, 0, 1, 2, 4, 5, 6, 10, 11, 12, 13, 14, 15, 16, 21, 23, 24, 25, 26, 27, 28, 31);
        SET_BIT(u32, 1, 25, 26);
        TEST_BITS_SET(u32, 1, 3, 7, 8, 9, 17, 18, 19, 20, 22, 25, 26, 29, 30);
        TEST_BITS_CLEAR(u32, 0, 2, 4, 5, 6, 10, 11, 12, 13, 14, 15, 16, 21, 23, 24, 27, 28, 31);
        CLEAR_BIT(u32, 29, 17, 1);
        TEST_BITS_SET(u32, 3, 7, 8, 9, 18, 19, 20, 22, 25, 26, 30);
        TEST_BITS_CLEAR(u32, 0, 1, 2, 4, 5, 6, 10, 11, 12, 13, 14, 15, 16, 17, 21, 23, 24, 27, 28, 29, 31);
        expected32 = 0;
        BIT_FOREACH(i, u32)
                expected32 |= UINT32_C(1) << i;
        assert_se(expected32 == u32);
        u32 = 0;
        TEST_BITS_CLEAR(u32, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31);
        BIT_FOREACH(i, u32)
                assert_se(0);
        u32 = ~u32;
        TEST_BITS_SET(u32, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31);
        count = 0;
        BIT_FOREACH(i, u32)
                count++;
        assert_se(count == 32);

        /* Test uint64_t */
        TEST_BITS_SET(0x18ba1400f4857460, 5, 6, 10, 12, 13, 14, 16, 18, 23, 26, 28, 29, 30, 31, 42, 44, 49, 51, 52, 53, 55, 59, 60);
        TEST_BITS_CLEAR(UINT64_C(0x18ba1400f4857460), 0, 1, 2, 3, 4, 7, 8, 9, 11, 15, 17, 19, 20, 21, 22, 24, 25, 27, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 43, 45, 46, 47, 48, 50, 54, 56, 57, 58, 61, 62, 63);
        uint64_t expected64 = 0;
        BIT_FOREACH(i, 0x18ba1400f4857460)
                expected64 |= UINT64_C(1) << i;
        assert_se(expected64 == 0x18ba1400f4857460);
        uint64_t u64 = 0xa90e2d8507a65739;
        TEST_BITS_SET(u64, 0, 3, 4, 5, 8, 9, 10, 12, 14, 17, 18, 21, 23, 24, 25, 26, 32, 34, 39, 40, 42, 43, 45, 49, 50, 51, 56, 59, 61, 63);
        TEST_BITS_CLEAR(u64, 1, 2, 6, 7, 11, 13, 15, 16, 19, 20, 22, 27, 28, 29, 30, 31, 33, 35, 36, 37, 38, 41, 44, 46, 47, 48, 52, 53, 54, 55, 57, 58, 60, 62);
        SET_BIT(u64, 1);
        TEST_BITS_SET(u64, 0, 1, 3, 4, 5, 8, 9, 10, 12, 14, 17, 18, 21, 23, 24, 25, 26, 32, 34, 39, 40, 42, 43, 45, 49, 50, 51, 56, 59, 61, 63);
        TEST_BITS_CLEAR(u64, 2, 6, 7, 11, 13, 15, 16, 19, 20, 22, 27, 28, 29, 30, 31, 33, 35, 36, 37, 38, 41, 44, 46, 47, 48, 52, 53, 54, 55, 57, 58, 60, 62);
        CLEAR_BIT(u64, 63);
        TEST_BITS_SET(u64, 0, 1, 3, 4, 5, 8, 9, 10, 12, 14, 17, 18, 21, 23, 24, 25, 26, 32, 34, 39, 40, 42, 43, 45, 49, 50, 51, 56, 59, 61);
        TEST_BITS_CLEAR(u64, 2, 6, 7, 11, 13, 15, 16, 19, 20, 22, 27, 28, 29, 30, 31, 33, 35, 36, 37, 38, 41, 44, 46, 47, 48, 52, 53, 54, 55, 57, 58, 60, 62, 63);
        SET_BIT(u64, 63, 62, 7, 13, 38);
        TEST_BITS_SET(u64, 0, 1, 3, 4, 5, 7, 8, 9, 10, 12, 13, 14, 17, 18, 21, 23, 24, 25, 26, 32, 34, 38, 39, 40, 42, 43, 45, 49, 50, 51, 56, 59, 61, 62, 63);
        TEST_BITS_CLEAR(u64, 2, 6, 11, 15, 16, 19, 20, 22, 27, 28, 29, 30, 31, 33, 35, 36, 37, 41, 44, 46, 47, 48, 52, 53, 54, 55, 57, 58, 60);
        CLEAR_BIT(u64, 0, 63, 32);
        TEST_BITS_SET(u64, 1, 3, 4, 5, 7, 8, 9, 10, 12, 13, 14, 17, 18, 21, 23, 24, 25, 26, 34, 38, 39, 40, 42, 43, 45, 49, 50, 51, 56, 59, 61, 62);
        TEST_BITS_CLEAR(u64, 0, 2, 6, 11, 15, 16, 19, 20, 22, 27, 28, 29, 30, 31, 32, 33, 35, 36, 37, 41, 44, 46, 47, 48, 52, 53, 54, 55, 57, 58, 60, 63);
        expected64 = 0;
        BIT_FOREACH(i, u64)
                expected64 |= UINT64_C(1) << i;
        assert_se(expected64 == u64);
        u64 = 0;
        TEST_BITS_CLEAR(u64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63);
        BIT_FOREACH(i, u64)
                assert_se(0);
        u64 = ~u64;
        TEST_BITS_SET(u64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63);
        count = 0;
        BIT_FOREACH(i, u64)
                count++;
        assert_se(count == 64);
}

TEST(DECIMAL_STR_WIDTH) {
        assert_se(DECIMAL_STR_WIDTH(0) == 1);
        assert_se(DECIMAL_STR_WIDTH(1) == 1);
        assert_se(DECIMAL_STR_WIDTH(2) == 1);
        assert_se(DECIMAL_STR_WIDTH(9) == 1);
        assert_se(DECIMAL_STR_WIDTH(10) == 2);
        assert_se(DECIMAL_STR_WIDTH(11) == 2);
        assert_se(DECIMAL_STR_WIDTH(99) == 2);
        assert_se(DECIMAL_STR_WIDTH(100) == 3);
        assert_se(DECIMAL_STR_WIDTH(101) == 3);
        assert_se(DECIMAL_STR_WIDTH(-1) == 2);
        assert_se(DECIMAL_STR_WIDTH(-2) == 2);
        assert_se(DECIMAL_STR_WIDTH(-9) == 2);
        assert_se(DECIMAL_STR_WIDTH(-10) == 3);
        assert_se(DECIMAL_STR_WIDTH(-11) == 3);
        assert_se(DECIMAL_STR_WIDTH(-99) == 3);
        assert_se(DECIMAL_STR_WIDTH(-100) == 4);
        assert_se(DECIMAL_STR_WIDTH(-101) == 4);
        assert_se(DECIMAL_STR_WIDTH(UINT64_MAX) == STRLEN("18446744073709551615"));
        assert_se(DECIMAL_STR_WIDTH(INT64_MAX) == STRLEN("9223372036854775807"));
        assert_se(DECIMAL_STR_WIDTH(INT64_MIN) == STRLEN("-9223372036854775808"));
}

TEST(DECIMAL_STR_MAX) {
        int8_t s8_longest = INT8_MIN;
        int16_t s16_longest = INT16_MIN;
        int32_t s32_longest = INT32_MIN;
        int64_t s64_longest = INT64_MIN;
        uint8_t u8_longest = UINT8_MAX;
        uint16_t u16_longest = UINT16_MAX;
        uint32_t u32_longest = UINT32_MAX;
        uint64_t u64_longest = UINT64_MAX;

        /* NB: Always add +1, because DECIMAL_STR_MAX() includes space for trailing NUL byte, but
         * DECIMAL_STR_WIDTH() does not! */
        assert_se(DECIMAL_STR_MAX(int8_t) == DECIMAL_STR_WIDTH(s8_longest)+1);
        assert_se(DECIMAL_STR_MAX(int16_t) == DECIMAL_STR_WIDTH(s16_longest)+1);
        assert_se(DECIMAL_STR_MAX(int32_t) == DECIMAL_STR_WIDTH(s32_longest)+1);
        assert_se(DECIMAL_STR_MAX(int64_t) == DECIMAL_STR_WIDTH(s64_longest)+1);

        assert_se(DECIMAL_STR_MAX(uint8_t) == DECIMAL_STR_WIDTH(u8_longest)+1);
        assert_se(DECIMAL_STR_MAX(uint16_t) == DECIMAL_STR_WIDTH(u16_longest)+1);
        assert_se(DECIMAL_STR_MAX(uint32_t) == DECIMAL_STR_WIDTH(u32_longest)+1);
        assert_se(DECIMAL_STR_MAX(uint64_t) == DECIMAL_STR_WIDTH(u64_longest)+1);
}

TEST(PTR_SUB1) {
        static const uint64_t x[4] = { 2, 3, 4, 5 };
        const uint64_t *p;

        p = x + ELEMENTSOF(x)-1;
        assert_se(*p == 5);

        p = PTR_SUB1(p, x);
        assert_se(*p == 4);

        p = PTR_SUB1(p, x);
        assert_se(*p == 3);

        p = PTR_SUB1(p, x);
        assert_se(*p == 2);

        p = PTR_SUB1(p, x);
        assert_se(!p);

        p = PTR_SUB1(p, x);
        assert_se(!p);
}

TEST(ISPOWEROF2) {
        uint64_t u;
        int64_t i;

        /* First, test constant expressions */
        assert_se(!ISPOWEROF2(-2));
        assert_se(!ISPOWEROF2(-1));
        assert_se(!ISPOWEROF2(0));
        assert_se(ISPOWEROF2(1));
        assert_se(ISPOWEROF2(2));
        assert_se(!ISPOWEROF2(3));
        assert_se(ISPOWEROF2(4));
        assert_se(!ISPOWEROF2(5));
        assert_se(!ISPOWEROF2(6));
        assert_se(!ISPOWEROF2(7));
        assert_se(ISPOWEROF2(8));
        assert_se(!ISPOWEROF2(9));
        assert_se(!ISPOWEROF2(1022));
        assert_se(ISPOWEROF2(1024));
        assert_se(!ISPOWEROF2(1025));
        assert_se(!ISPOWEROF2(UINT64_C(0xffffffff)));
        assert_se(ISPOWEROF2(UINT64_C(0x100000000)));
        assert_se(!ISPOWEROF2(UINT64_C(0x100000001)));

        /* Then, test dynamic expressions, and if they are side-effect free */
        i = -2;
        assert_se(!ISPOWEROF2(i++));
        assert_se(i == -1);
        assert_se(!ISPOWEROF2(i++));
        assert_se(i == 0);
        assert_se(!ISPOWEROF2(i++));
        assert_se(i == 1);
        assert_se(ISPOWEROF2(i++));
        assert_se(i == 2);
        assert_se(ISPOWEROF2(i++));
        assert_se(i == 3);
        assert_se(!ISPOWEROF2(i++));
        assert_se(i == 4);
        assert_se(ISPOWEROF2(i++));
        assert_se(i == 5);
        assert_se(!ISPOWEROF2(i));

        u = 0;
        assert_se(!ISPOWEROF2(u++));
        assert_se(u == 1);
        assert_se(ISPOWEROF2(u++));
        assert_se(u == 2);
        assert_se(ISPOWEROF2(u++));
        assert_se(u == 3);
        assert_se(!ISPOWEROF2(u++));
        assert_se(u == 4);
        assert_se(ISPOWEROF2(u++));
        assert_se(u == 5);
        assert_se(!ISPOWEROF2(u));
}

TEST(ALIGNED) {
        assert_se(IS_ALIGNED16(NULL));
        assert_se(IS_ALIGNED32(NULL));
        assert_se(IS_ALIGNED64(NULL));

        uint64_t u64;
        uint32_t u32;
        uint16_t u16;

        assert_se(IS_ALIGNED16(&u16));
        assert_se(IS_ALIGNED16(&u32));
        assert_se(IS_ALIGNED16(&u64));
        assert_se(IS_ALIGNED32(&u32));
        assert_se(IS_ALIGNED32(&u64));
        assert_se(IS_ALIGNED64(&u64));

        _align_(32) uint8_t ua256;
        _align_(8) uint8_t ua64;
        _align_(4) uint8_t ua32;
        _align_(2) uint8_t ua16;

        assert_se(IS_ALIGNED16(&ua256));
        assert_se(IS_ALIGNED32(&ua256));
        assert_se(IS_ALIGNED64(&ua256));

        assert_se(IS_ALIGNED16(&ua64));
        assert_se(IS_ALIGNED32(&ua64));
        assert_se(IS_ALIGNED64(&ua64));

        assert_se(IS_ALIGNED16(&ua32));
        assert_se(IS_ALIGNED32(&ua32));

        assert_se(IS_ALIGNED16(&ua16));

#ifdef __x86_64__
        /* Conditionalized on x86-64, since there we know for sure that all three types are aligned to
         * their size. Too lazy to figure it out for other archs */
        void *p = UINT_TO_PTR(1); /* definitely not aligned */
        assert_se(!IS_ALIGNED16(p));
        assert_se(!IS_ALIGNED32(p));
        assert_se(!IS_ALIGNED64(p));

        assert_se(IS_ALIGNED16(ALIGN2_PTR(p)));
        assert_se(IS_ALIGNED32(ALIGN4_PTR(p)));
        assert_se(IS_ALIGNED64(ALIGN8_PTR(p)));

        p = UINT_TO_PTR(-1); /* also definitely not aligned */
        assert_se(!IS_ALIGNED16(p));
        assert_se(!IS_ALIGNED32(p));
        assert_se(!IS_ALIGNED64(p));
#endif
}

DEFINE_TEST_MAIN(LOG_INFO);
