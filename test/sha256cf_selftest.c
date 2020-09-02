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

#include "../src/sha256cf.h"

#define LENGTH_PADDING(L) do {                                    \
    block[64 - 8] = ((unsigned long)(L) >> (56 - 3)) & 0xff;      \
    block[64 - 7] = ((unsigned long)(L) >> (48 - 3)) & 0xff;      \
    block[64 - 6] = ((unsigned long)(L) >> (40 - 3)) & 0xff;      \
    block[64 - 5] = ((unsigned long)(L) >> (32 - 3)) & 0xff;      \
    block[64 - 4] = ((unsigned long)(L) >> (24 - 3)) & 0xff;      \
    block[64 - 3] = ((unsigned long)(L) >> (16 - 3)) & 0xff;      \
    block[64 - 2] = ((unsigned long)(L) >> ( 8 - 3)) & 0xff;      \
    block[64 - 1] = ((unsigned long)(L) <<       3 ) & 0xff;      \
  } while (0)

#define FINALIZER 0x80

static void check_str0(void) {
  uint8_t st[SHA256CF_MEMSTATESIZE];
  uint8_t block[SHA256CF_BLOCKSIZE];
  uint8_t buf[SHA256CF_STATESIZE];
  const uint8_t res[] = {
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
    0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
    0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
  };

  sha256cf_init(st);
  memset(block, 0, 64);
  block[0] = FINALIZER;
  LENGTH_PADDING(0);
  sha256cf_update(st, block);
  sha256cf_export(st, buf);
  sha256cf_clear(st);
  if (memcmp(buf, res, SHA256CF_STATESIZE)) {
    fprintf(stderr, "FATAL: Wrong hash value for string <0>\n");
    exit(1);
  }
}

static void check_str3(void) {
  uint8_t st[SHA256CF_MEMSTATESIZE];
  uint8_t block[SHA256CF_BLOCKSIZE];
  uint8_t buf[SHA256CF_STATESIZE];
  const uint8_t res[] = {
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
    0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
  };

  sha256cf_init(st);
  memset(block, 0, 64);
  memcpy(block, "abc", 3);
  block[3] = FINALIZER;
  LENGTH_PADDING(3);
  sha256cf_update(st, block);
  sha256cf_export(st, buf);
  sha256cf_clear(st);
  if (memcmp(buf, res, SHA256CF_STATESIZE)) {
    fprintf(stderr, "FATAL: Wrong hash value for string <3>\n");
    exit(1);
  }
}

#define STR56 "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"

static void check_str56(void) {
  uint8_t st[SHA256CF_MEMSTATESIZE];
  uint8_t block[SHA256CF_BLOCKSIZE];
  uint8_t buf[SHA256CF_STATESIZE];
  const uint8_t res[] = {
    0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
    0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
    0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
    0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1,
  };

  _Static_assert(strlen(STR56) == 56, "STR56 has wrong length");

  sha256cf_init(st);
  memset(block, 0, 64);
  memcpy(block, STR56, 56);
  block[56] = FINALIZER;
  sha256cf_update(st, block);
  memset(block, 0, 64);
  LENGTH_PADDING(56);
  sha256cf_update(st, block);
  sha256cf_export(st, buf);
  sha256cf_clear(st);
  if (memcmp(buf, res, SHA256CF_STATESIZE)) {
    fprintf(stderr, "FATAL: Wrong hash value for string <56>\n");
    exit(1);
  }
}

#define STR112 "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"

static void check_str112(void) {
  uint8_t st[SHA256CF_MEMSTATESIZE];
  uint8_t block[SHA256CF_BLOCKSIZE];
  uint8_t buf[SHA256CF_STATESIZE];
  const uint8_t res[] = {
    0xcf, 0x5b, 0x16, 0xa7, 0x78, 0xaf, 0x83, 0x80,
    0x03, 0x6c, 0xe5, 0x9e, 0x7b, 0x04, 0x92, 0x37,
    0x0b, 0x24, 0x9b, 0x11, 0xe8, 0xf0, 0x7a, 0x51,
    0xaf, 0xac, 0x45, 0x03, 0x7a, 0xfe, 0xe9, 0xd1,
  };

  _Static_assert(strlen(STR112) == 112, "STR112 has wrong length");
  _Static_assert(112 == 64 + 48, "math error");

  sha256cf_init(st);
  memcpy(block, STR112, 64);
  sha256cf_update(st, block);
  memset(block, 0, 64);
  memcpy(block, STR112 + 64, 48);
  block[48] = FINALIZER;
  LENGTH_PADDING(112);
  sha256cf_update(st, block);
  sha256cf_export(st, buf);
  sha256cf_clear(st);
  if (memcmp(buf, res, SHA256CF_STATESIZE)) {
    fprintf(stderr, "FATAL: Wrong hash value for string <112>\n");
    exit(1);
  }
}

static void check_str1000000(void) {
  uint8_t st[SHA256CF_MEMSTATESIZE];
  uint8_t block[SHA256CF_BLOCKSIZE];
  uint8_t buf[SHA256CF_STATESIZE];
  const uint8_t res[] = {
    0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92,
    0x81, 0xa1, 0xc7, 0xe2, 0x84, 0xd7, 0x3e, 0x67,
    0xf1, 0x80, 0x9a, 0x48, 0xa4, 0x97, 0x20, 0x0e,
    0x04, 0x6d, 0x39, 0xcc, 0xc7, 0x11, 0x2c, 0xd0,
  };
  int i;

  _Static_assert(1000000UL == 15625 * 64 + 0, "math error");

  sha256cf_init(st);
  memset(block, 'a', 64);
  for (i = 0; i < 15625; i++) {
    sha256cf_update(st, block);
  }
  memset(block, 0, 64);
  block[0] = FINALIZER;
  LENGTH_PADDING(1000000UL);
  sha256cf_update(st, block);
  sha256cf_export(st, buf);
  sha256cf_clear(st);
  if (memcmp(buf, res, SHA256CF_STATESIZE)) {
    fprintf(stderr, "FATAL: Wrong hash value for string <1000000>\n");
    exit(1);
  }
}

#define STR_HUGE_FRAGMENT "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
#define STR_HUGE_REPS 16777216UL
#define STR_HUGE_TOTALLEN (64 * STR_HUGE_REPS)

static void check_strHUGE(void) {
  uint8_t st[SHA256CF_MEMSTATESIZE];
  uint8_t block[SHA256CF_BLOCKSIZE];
  uint8_t buf[SHA256CF_STATESIZE];
  const uint8_t res[] = {
    0x50, 0xe7, 0x2a, 0x0e, 0x26, 0x44, 0x2f, 0xe2,
    0x55, 0x2d, 0xc3, 0x93, 0x8a, 0xc5, 0x86, 0x58,
    0x22, 0x8c, 0x0c, 0xbf, 0xb1, 0xd2, 0xca, 0x87,
    0x2a, 0xe4, 0x35, 0x26, 0x6f, 0xcd, 0x05, 0x5e,
  };
  unsigned long i;

  _Static_assert(strlen(STR_HUGE_FRAGMENT) == 64, "STR_HUGE_FRAGMENT has wrong length");

  sha256cf_init(st);
  memcpy(block, STR_HUGE_FRAGMENT, 64);
  for (i = 0; i < STR_HUGE_REPS; i++) {
    sha256cf_update(st, block);
  }
  memset(block, 0, 64);
  block[0] = FINALIZER;
  LENGTH_PADDING(STR_HUGE_TOTALLEN);
  sha256cf_update(st, block);
  sha256cf_export(st, buf);
  sha256cf_clear(st);
  if (memcmp(buf, res, SHA256CF_STATESIZE)) {
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
