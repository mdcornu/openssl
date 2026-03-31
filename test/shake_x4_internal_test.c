/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2026 Intel Corporation. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Internal tests for SHAKE x4 multi-buffer wrappers.
 */

#include <string.h>
#include <openssl/opensslconf.h>
#include "testutil.h"

#if defined(KECCAK1600_ASM) && defined(__x86_64__) && !defined(OPENSSL_NO_ASM)
#include "internal/sha3.h"

static const unsigned char lane0[64] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f
};

static const unsigned char lane1[64] = {
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
    0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
    0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f
};

static const unsigned char lane2[64] = {
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
    0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf
};

static const unsigned char lane3[64] = {
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
    0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
    0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
    0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};

static int test_shake128_x4_single_call(void)
{
    static const size_t outlen = 97;
    unsigned char oneshot0[outlen], oneshot1[outlen], oneshot2[outlen], oneshot3[outlen];
    unsigned char incr0[outlen], incr1[outlen], incr2[outlen], incr3[outlen];
    unsigned char swap0[outlen], swap1[outlen], swap2[outlen], swap3[outlen];
    KECCAK1600_X4_CTX ctx;

    if (!SHA3_avx512vl_capable())
        return TEST_skip("SHAKE x4 AVX-512VL path not supported on this CPU");

    ossl_sha3_shake128_x4(oneshot0, oneshot1, oneshot2, oneshot3, outlen,
        lane0, lane1, lane2, lane3, sizeof(lane0));

    ossl_sha3_shake128_x4_inc_init(&ctx);
    ossl_sha3_shake128_x4_inc_absorb(&ctx,
        lane0, lane1, lane2, lane3, sizeof(lane0));
    ossl_sha3_shake128_x4_inc_finalize(&ctx);
    ossl_sha3_shake128_x4_inc_squeeze(incr0, incr1, incr2, incr3, outlen, &ctx);

    if (!TEST_mem_eq(oneshot0, outlen, incr0, outlen)
        || !TEST_mem_eq(oneshot1, outlen, incr1, outlen)
        || !TEST_mem_eq(oneshot2, outlen, incr2, outlen)
        || !TEST_mem_eq(oneshot3, outlen, incr3, outlen))
        return 0;

    /*
     * Swap lane0 and lane1 inputs and verify outputs swap in the same way.
     * This validates lane mapping/independence in the x4 API.
     */
    ossl_sha3_shake128_x4(swap0, swap1, swap2, swap3, outlen,
        lane1, lane0, lane2, lane3, sizeof(lane0));

    return TEST_mem_eq(oneshot1, outlen, swap0, outlen)
        && TEST_mem_eq(oneshot0, outlen, swap1, outlen)
        && TEST_mem_eq(oneshot2, outlen, swap2, outlen)
        && TEST_mem_eq(oneshot3, outlen, swap3, outlen);
}

static int test_shake256_x4_incremental(void)
{
    static const size_t outlen = 131;
    static const size_t split = 19;
    unsigned char out0[outlen], out1[outlen], out2[outlen], out3[outlen];
    unsigned char auto0[outlen], auto1[outlen], auto2[outlen], auto3[outlen];
    KECCAK1600_X4_CTX ctx;

    if (!SHA3_avx512vl_capable())
        return TEST_skip("SHAKE x4 AVX-512VL path not supported on this CPU");

    ossl_sha3_shake256_x4_inc_init(&ctx);
    if (!TEST_size_t_eq(ctx.rate, 136) || !TEST_uint_eq(ctx.finalized, 0))
        return 0;

    ossl_sha3_shake256_x4_inc_absorb(&ctx,
        lane0, lane1, lane2, lane3, split);
    ossl_sha3_shake256_x4_inc_absorb(&ctx,
        lane0 + split, lane1 + split,
        lane2 + split, lane3 + split,
        sizeof(lane0) - split);
    ossl_sha3_shake256_x4_inc_finalize(&ctx);
    ossl_sha3_shake256_x4_inc_squeeze(out0, out1, out2, out3, outlen, &ctx);

    /* Validate auto-finalize behavior on first squeeze yields same stream. */
    ossl_sha3_shake256_x4_inc_init(&ctx);
    ossl_sha3_shake256_x4_inc_absorb(&ctx,
        lane0, lane1, lane2, lane3, split);
    ossl_sha3_shake256_x4_inc_absorb(&ctx,
        lane0 + split, lane1 + split,
        lane2 + split, lane3 + split,
        sizeof(lane0) - split);
    ossl_sha3_shake256_x4_inc_squeeze(auto0, auto1, auto2, auto3, outlen, &ctx);

    return TEST_uint_eq(ctx.finalized, 1)
        && TEST_mem_eq(out0, outlen, auto0, outlen)
        && TEST_mem_eq(out1, outlen, auto1, outlen)
        && TEST_mem_eq(out2, outlen, auto2, outlen)
        && TEST_mem_eq(out3, outlen, auto3, outlen);
}
#endif

int setup_tests(void)
{
#ifdef OPENSSL_CPUID_OBJ
    OPENSSL_cpuid_setup();
#endif

#if defined(KECCAK1600_ASM) && defined(__x86_64__) && !defined(OPENSSL_NO_ASM)
    ADD_TEST(test_shake128_x4_single_call);
    ADD_TEST(test_shake256_x4_incremental);
#else
    TEST_note("SHAKE x4 internal test is not supported in this build");
#endif
    return 1;
}
