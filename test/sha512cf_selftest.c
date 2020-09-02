/*
  Copyright 2020 IBM Corp.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

/***
 * test vectors from
 *   https://www.di-mgt.com.au/sha_testvectors.html
 * and
 *   http://www.iwar.org.uk/comsec/resources/cipher/sha256-384-512.pdf
 ***/

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../src/sha512cf.h"

/* note that this considers only 64 of 128 bits */
#define LENGTH_PADDING(L) do {                                    \
    block[128 - 8] = ((unsigned long)(L) >> (56 - 3)) & 0xff;     \
    block[128 - 7] = ((unsigned long)(L) >> (48 - 3)) & 0xff;     \
    block[128 - 6] = ((unsigned long)(L) >> (40 - 3)) & 0xff;     \
    block[128 - 5] = ((unsigned long)(L) >> (32 - 3)) & 0xff;     \
    block[128 - 4] = ((unsigned long)(L) >> (24 - 3)) & 0xff;     \
    block[128 - 3] = ((unsigned long)(L) >> (16 - 3)) & 0xff;     \
    block[128 - 2] = ((unsigned long)(L) >> ( 8 - 3)) & 0xff;     \
    block[128 - 1] = ((unsigned long)(L) <<       3 ) & 0xff;     \
  } while (0)

#define FINALIZER 0x80

static void check_str0(void) {
  uint8_t st[SHA512CF_MEMSTATESIZE];
  uint8_t block[SHA512CF_BLOCKSIZE];
  uint8_t buf[SHA512CF_STATESIZE];
  const uint8_t res[] = {
    0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd,
    0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
    0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
    0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
    0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0,
    0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
    0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
    0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e,
  };

  sha512cf_init(st);
  memset(block, 0, 128);
  block[0] = FINALIZER;
  LENGTH_PADDING(0);
  sha512cf_update(st, block);
  sha512cf_export(st, buf);
  sha512cf_clear(st);
  if (memcmp(buf, res, SHA512CF_STATESIZE)) {
    fprintf(stderr, "FATAL: Wrong hash value for string <0>\n");
    exit(1);
  }
}

static void check_str3(void) {
  uint8_t st[SHA512CF_MEMSTATESIZE];
  uint8_t block[SHA512CF_BLOCKSIZE];
  uint8_t buf[SHA512CF_STATESIZE];
  const uint8_t res[] = {
    0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
    0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
    0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
    0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
    0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
    0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
    0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
    0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
  };

  sha512cf_init(st);
  memset(block, 0, 128);
  memcpy(block, "abc", 3);
  block[3] = FINALIZER;
  LENGTH_PADDING(3);
  sha512cf_update(st, block);
  sha512cf_export(st, buf);
  sha512cf_clear(st);
  if (memcmp(buf, res, SHA512CF_STATESIZE)) {
    fprintf(stderr, "FATAL: Wrong hash value for string <3>\n");
    exit(1);
  }
}

#define STR56 "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"

static void check_str56(void) {
  uint8_t st[SHA512CF_MEMSTATESIZE];
  uint8_t block[SHA512CF_BLOCKSIZE];
  uint8_t buf[SHA512CF_STATESIZE];
  const uint8_t res[] = {
    0x20, 0x4a, 0x8f, 0xc6, 0xdd, 0xa8, 0x2f, 0x0a,
    0x0c, 0xed, 0x7b, 0xeb, 0x8e, 0x08, 0xa4, 0x16,
    0x57, 0xc1, 0x6e, 0xf4, 0x68, 0xb2, 0x28, 0xa8,
    0x27, 0x9b, 0xe3, 0x31, 0xa7, 0x03, 0xc3, 0x35,
    0x96, 0xfd, 0x15, 0xc1, 0x3b, 0x1b, 0x07, 0xf9,
    0xaa, 0x1d, 0x3b, 0xea, 0x57, 0x78, 0x9c, 0xa0,
    0x31, 0xad, 0x85, 0xc7, 0xa7, 0x1d, 0xd7, 0x03,
    0x54, 0xec, 0x63, 0x12, 0x38, 0xca, 0x34, 0x45,
  };

  _Static_assert(strlen(STR56) == 56, "STR56 has wrong length");

  sha512cf_init(st);
  memset(block, 0, 128);
  memcpy(block, STR56, 56);
  block[56] = FINALIZER;
  LENGTH_PADDING(56);
  sha512cf_update(st, block);
  sha512cf_export(st, buf);
  sha512cf_clear(st);
  if (memcmp(buf, res, SHA512CF_STATESIZE)) {
    fprintf(stderr, "FATAL: Wrong hash value for string <56>\n");
    exit(1);
  }
}

#define STR112 "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"

static void check_str112(void) {
  uint8_t st[SHA512CF_MEMSTATESIZE];
  uint8_t block[SHA512CF_BLOCKSIZE];
  uint8_t buf[SHA512CF_STATESIZE];
  const uint8_t res[] = {
    0x8e, 0x95, 0x9b, 0x75, 0xda, 0xe3, 0x13, 0xda,
    0x8c, 0xf4, 0xf7, 0x28, 0x14, 0xfc, 0x14, 0x3f,
    0x8f, 0x77, 0x79, 0xc6, 0xeb, 0x9f, 0x7f, 0xa1,
    0x72, 0x99, 0xae, 0xad, 0xb6, 0x88, 0x90, 0x18,
    0x50, 0x1d, 0x28, 0x9e, 0x49, 0x00, 0xf7, 0xe4,
    0x33, 0x1b, 0x99, 0xde, 0xc4, 0xb5, 0x43, 0x3a,
    0xc7, 0xd3, 0x29, 0xee, 0xb6, 0xdd, 0x26, 0x54,
    0x5e, 0x96, 0xe5, 0x5b, 0x87, 0x4b, 0xe9, 0x09,
  };

  _Static_assert(strlen(STR112) == 112, "STR112 has wrong length");

  sha512cf_init(st);
  memset(block, 0, 128);
  memcpy(block, STR112, 112);
  block[112] = FINALIZER;
  sha512cf_update(st, block);
  memset(block, 0, 128);
  LENGTH_PADDING(112);
  sha512cf_update(st, block);
  sha512cf_export(st, buf);
  sha512cf_clear(st);
  if (memcmp(buf, res, SHA512CF_STATESIZE)) {
    fprintf(stderr, "FATAL: Wrong hash value for string <112>\n");
    exit(1);
  }
}

static void check_str1000000(void) {
  uint8_t st[SHA512CF_MEMSTATESIZE];
  uint8_t block[SHA512CF_BLOCKSIZE];
  uint8_t buf[SHA512CF_STATESIZE];
  const uint8_t res[] = {
    0xe7, 0x18, 0x48, 0x3d, 0x0c, 0xe7, 0x69, 0x64,
    0x4e, 0x2e, 0x42, 0xc7, 0xbc, 0x15, 0xb4, 0x63,
    0x8e, 0x1f, 0x98, 0xb1, 0x3b, 0x20, 0x44, 0x28,
    0x56, 0x32, 0xa8, 0x03, 0xaf, 0xa9, 0x73, 0xeb,
    0xde, 0x0f, 0xf2, 0x44, 0x87, 0x7e, 0xa6, 0x0a,
    0x4c, 0xb0, 0x43, 0x2c, 0xe5, 0x77, 0xc3, 0x1b,
    0xeb, 0x00, 0x9c, 0x5c, 0x2c, 0x49, 0xaa, 0x2e,
    0x4e, 0xad, 0xb2, 0x17, 0xad, 0x8c, 0xc0, 0x9b,
  };
  int i;

  _Static_assert(1000000UL == 7812 * 128 + 64, "math error");

  sha512cf_init(st);
  memset(block, 'a', 128);
  for (i = 0; i < 7812; i++) {
    sha512cf_update(st, block);
  }
  memset(block + 64, 0, 64);
  block[64] = FINALIZER;
  LENGTH_PADDING(1000000UL);
  sha512cf_update(st, block);
  sha512cf_export(st, buf);
  sha512cf_clear(st);
  if (memcmp(buf, res, SHA512CF_STATESIZE)) {
    fprintf(stderr, "FATAL: Wrong hash value for string <1000000>\n");
    exit(1);
  }
}

#define STR_HUGE_FRAGMENT "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
#define STR_HUGE_REPS (16777216ULL / 2)
#define STR_HUGE_TOTALLEN (128 * STR_HUGE_REPS)

static void check_strHUGE(void) {
  uint8_t st[SHA512CF_MEMSTATESIZE];
  uint8_t block[SHA512CF_BLOCKSIZE];
  uint8_t buf[SHA512CF_STATESIZE];
  const uint8_t res[] = {
    0xb4, 0x7c, 0x93, 0x34, 0x21, 0xea, 0x2d, 0xb1,
    0x49, 0xad, 0x6e, 0x10, 0xfc, 0xe6, 0xc7, 0xf9,
    0x3d, 0x07, 0x52, 0x38, 0x01, 0x80, 0xff, 0xd7,
    0xf4, 0x62, 0x9a, 0x71, 0x21, 0x34, 0x83, 0x1d,
    0x77, 0xbe, 0x60, 0x91, 0xb8, 0x19, 0xed, 0x35,
    0x2c, 0x29, 0x67, 0xa2, 0xe2, 0xd4, 0xfa, 0x50,
    0x50, 0x72, 0x3c, 0x96, 0x30, 0x69, 0x1f, 0x1a,
    0x05, 0xa7, 0x28, 0x1d, 0xbe, 0x6c, 0x10, 0x86,
  };
  unsigned long i;

  _Static_assert(strlen(STR_HUGE_FRAGMENT) == 64, "STR_HUGE_FRAGMENT has wrong length");

  sha512cf_init(st);
  memcpy(block, STR_HUGE_FRAGMENT, 64);
  memcpy(block + 64, STR_HUGE_FRAGMENT, 64);
  for (i = 0; i < STR_HUGE_REPS; i++) {
    sha512cf_update(st, block);
  }
  memset(block, 0, 128);
  block[0] = FINALIZER;
  LENGTH_PADDING(STR_HUGE_TOTALLEN);
  sha512cf_update(st, block);
  sha512cf_export(st, buf);
  sha512cf_clear(st);
  if (memcmp(buf, res, SHA512CF_STATESIZE)) {
    fprintf(stderr, "FATAL: Wrong hash value for string <HUGE>\n");
    exit(1);
  }
}

int main(void) {
  check_str0();
  check_str3();
  check_str56();
  check_str112();
  check_str1000000();
  check_strHUGE();

  printf("All tests passed successfully.\n");
  exit(0);
}
