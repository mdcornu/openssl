#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use OpenSSL::Test;              # get 'plan'
use OpenSSL::Test::Simple;
use OpenSSL::Test::Utils;

setup("test_internal_shake_x4");

plan skip_all => "SHAKE x4 internal test is x86_64 AVX-512VL only"
    if config('target') !~ m/x86_64/;

simple_test("test_internal_shake_x4", "shake_x4_internal_test", "sha3", "asm");
