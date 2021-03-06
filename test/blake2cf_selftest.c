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

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../src/blake2cf.h"

/* known-answer test */
static void kat(int klen, const uint8_t *key, int mdlen, int mlen, const uint8_t *m, const uint8_t *known_answer) {
  /*
   *  DON'T USE THIS FOR PRODUCTION
   *  (reason: side cases like mlen == 0 are not handled correctly, the keying was only tested on two key sizes, etc.)
   */
  uint8_t block[BLAKE2CF_BLOCKSIZE];
  uint8_t st[BLAKE2CF_MEMSTATESIZE];
  uint8_t md[BLAKE2CF_STATESIZE];
  unsigned long long ctr;

  blake2cf_init(st, klen, mdlen);

  ctr = 0;

  if (klen) {
    memcpy(block, key, klen);
    memset(block + klen, 0, BLAKE2CF_BLOCKSIZE - klen);
    ctr += BLAKE2CF_BLOCKSIZE;
    blake2cf_update(st, block, ctr, 0);
  }

  while (mlen > BLAKE2CF_BLOCKSIZE) {
    ctr += BLAKE2CF_BLOCKSIZE;
    blake2cf_update(st, m, ctr, 0);
    m += BLAKE2CF_BLOCKSIZE, mlen -= BLAKE2CF_BLOCKSIZE;
  }

  memcpy(block, m, mlen);
  memset(block + mlen, 0, BLAKE2CF_BLOCKSIZE - mlen);
  ctr += mlen;
  blake2cf_update(st, block, ctr, 1);

  blake2cf_export(st, md);

  if (memcmp(md, known_answer, mdlen)) {
    fprintf(stderr, "FATAL: Wrong hash value!\n");
    exit(1);
  }
}

#define M 1048576
static void unkeyed(void) {
  static const uint8_t b2sum_abc_512[] = { /* echo -n "abc" | b2sum -l 512 */
    0xba, 0x80, 0xa5, 0x3f, 0x98, 0x1c, 0x4d, 0x0d, 0x6a, 0x27, 0x97, 0xb6, 0x9f, 0x12, 0xf6, 0xe9,
    0x4c, 0x21, 0x2f, 0x14, 0x68, 0x5a, 0xc4, 0xb7, 0x4b, 0x12, 0xbb, 0x6f, 0xdb, 0xff, 0xa2, 0xd1,
    0x7d, 0x87, 0xc5, 0x39, 0x2a, 0xab, 0x79, 0x2d, 0xc2, 0x52, 0xd5, 0xde, 0x45, 0x33, 0xcc, 0x95,
    0x18, 0xd3, 0x8a, 0xa8, 0xdb, 0xf1, 0x92, 0x5a, 0xb9, 0x23, 0x86, 0xed, 0xd4, 0x00, 0x99, 0x23,
  };

  static const uint8_t b2sum_abc_256[] = { /* echo -n "abc" | b2sum -l 256 */
    0xbd, 0xdd, 0x81, 0x3c, 0x63, 0x42, 0x39, 0x72, 0x31, 0x71, 0xef, 0x3f, 0xee, 0x98, 0x57, 0x9b,
    0x94, 0x96, 0x4e, 0x3b, 0xb1, 0xcb, 0x3e, 0x42, 0x72, 0x62, 0xc8, 0xc0, 0x68, 0xd5, 0x23, 0x19,
  };

  static const uint8_t b2sum_a_32[] = { /* echo -n "a" | b2sum -l 32 */
    0xca, 0x23, 0x4c, 0x55,
  };

  static const uint8_t b2sum__32[] = { /* echo -n "" | b2sum -l 32 */
    0x12, 0x71, 0xcf, 0x25,
  };

  static const uint8_t b2sum_a127_256[] = { /* yes a | head -127 | tr -d "\n" | b2sum -l 256 */
    0x59, 0xe2, 0xf1, 0xab, 0xa2, 0x40, 0xf2, 0x0a, 0xa5, 0x91, 0x01, 0x6f, 0x5e, 0xf4, 0x29, 0x99,
    0x0b, 0xc9, 0xc2, 0x13, 0x1d, 0xcd, 0x0d, 0x30, 0xf0, 0xff, 0xd7, 0x5e, 0xd1, 0x8f, 0x31, 0x7d,
  };

  static const uint8_t b2sum_a128_256[] = { /* yes a | head -128 | tr -d "\n" | b2sum -l 256 */
    0xae, 0x2a, 0xa4, 0x85, 0x07, 0x88, 0x5c, 0x4c, 0x95, 0x0f, 0xb8, 0x09, 0xb2, 0x07, 0x6f, 0x95,
    0x9c, 0xde, 0x9f, 0x8e, 0xa6, 0xda, 0x26, 0x0d, 0x9a, 0x35, 0x87, 0xdf, 0x33, 0xda, 0xc4, 0x50,
  };

  static const uint8_t b2sum_a129_256[] = { /* yes a | head -129 | tr -d "\n" | b2sum -l 256 */
    0x2f, 0x64, 0x74, 0x4a, 0x6d, 0xe0, 0xd2, 0xc0, 0xb5, 0x6e, 0x64, 0xcf, 0x6e, 0x29, 0xa5, 0xaa,
    0xa2, 0x55, 0x01, 0x0d, 0x41, 0x5d, 0x51, 0xc7, 0x5c, 0xcc, 0x82, 0xf7, 0x3d, 0xcc, 0xd8, 0x65,
  };

  static const uint8_t b2sum_a1M_128[] = { /* yes a | head -1048576 | tr -d "\n" | b2sum -l 128 */
    0xc0, 0x8b, 0x59, 0x10, 0x12, 0x6f, 0x45, 0x7f, 0x04, 0xfa, 0xfd, 0xd0, 0x4e, 0x92, 0xe5, 0x46,
  };

  uint8_t buf[M];

  kat(0, NULL, 64, 3, (uint8_t*)"abc", b2sum_abc_512);
  kat(0, NULL, 32, 3, (uint8_t*)"abc", b2sum_abc_256);

  memset(buf, 'a', M);
  kat(0, NULL, 4, 1, buf, b2sum_a_32);
  kat(0, NULL, 4, 0, buf, b2sum__32);
  kat(0, NULL, 32, 127, buf, b2sum_a127_256);
  kat(0, NULL, 32, 128, buf, b2sum_a128_256);
  kat(0, NULL, 32, 129, buf, b2sum_a129_256);
  kat(0, NULL, 16, M, buf, b2sum_a1M_128);
}
#undef M

/* test vectors from https://github.com/BLAKE2/BLAKE2/blob/master/testvectors/blake2b-kat.txt */
static void keyed(void) {
  static const uint8_t b2prf_1_512[] = {
    0x96, 0x1f, 0x6d, 0xd1, 0xe4, 0xdd, 0x30, 0xf6, 0x39, 0x01, 0x69, 0x0c, 0x51, 0x2e, 0x78, 0xe4,
    0xb4, 0x5e, 0x47, 0x42, 0xed, 0x19, 0x7c, 0x3c, 0x5e, 0x45, 0xc5, 0x49, 0xfd, 0x25, 0xf2, 0xe4,
    0x18, 0x7b, 0x0b, 0xc9, 0xfe, 0x30, 0x49, 0x2b, 0x16, 0xb0, 0xd0, 0xbc, 0x4e, 0xf9, 0xb0, 0xf3,
    0x4c, 0x70, 0x03, 0xfa, 0xc0, 0x9a, 0x5e, 0xf1, 0x53, 0x2e, 0x69, 0x43, 0x02, 0x34, 0xce, 0xbd,
  };
  static const uint8_t b2prf_255_512[] = {
    0x14, 0x27, 0x09, 0xd6, 0x2e, 0x28, 0xfc, 0xcc, 0xd0, 0xaf, 0x97, 0xfa, 0xd0, 0xf8, 0x46, 0x5b,
    0x97, 0x1e, 0x82, 0x20, 0x1d, 0xc5, 0x10, 0x70, 0xfa, 0xa0, 0x37, 0x2a, 0xa4, 0x3e, 0x92, 0x48,
    0x4b, 0xe1, 0xc1, 0xe7, 0x3b, 0xa1, 0x09, 0x06, 0xd5, 0xd1, 0x85, 0x3d, 0xb6, 0xa4, 0x10, 0x6e,
    0x0a, 0x7b, 0xf9, 0x80, 0x0d, 0x37, 0x3d, 0x6d, 0xee, 0x2d, 0x46, 0xd6, 0x2e, 0xf2, 0xa4, 0x61,
  };

  uint8_t in[255];
  uint8_t key[64];
  int i;

  for (i = 0; i < 255; i++) {
    in[i] = i;
  }
  for (i = 0; i < 64; i++) {
    key[i] = i;
  }
  kat(64, key, 64, 1, in, b2prf_1_512);
  kat(64, key, 64, 255, in, b2prf_255_512);
}

int main(void) {
  unkeyed();
  keyed();

  printf("All tests passed successfully.\n");
  exit(0);
}
