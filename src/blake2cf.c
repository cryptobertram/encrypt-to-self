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

#define _DEFAULT_SOURCE /* activates  htole64  and  le64toh  from endian.h */
#include <stdint.h>
#include <endian.h>
#include "blake2cf.h"

#define assert(C) do { ; } while (! (C)) /* poor man's assert */

_Static_assert(sizeof(uint64_t[8]) == BLAKE2CF_MEMSTATESIZE, "BLAKE2CF_MEMSTATESIZE has wrong value!");

static const uint64_t iv[8] = {
  0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
  0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
};

static const uint8_t sigma[10 * 16] = {
   0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
  14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3,
  11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4,
   7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8,
   9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13,
   2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9,
  12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11,
  13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10,
   6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5,
  10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0,
};

void blake2cf_init(void * _st, int klen, int mdlen) {
  uint64_t *st = _st;
  int i;

  assert(klen >= 0 && klen <= 64);
  assert(mdlen >= 1 && mdlen <= 64);

  for (i = 0; i < 8; i++) {
    st[i] = iv[i];
  }
  st[0] ^= 0x01010000 | (klen << 8) | (mdlen);
}

void blake2cf_clear(void * _st) {
  uint64_t *st = _st;
  int i;
  for (i = 0; i < 8; i++) {
    st[i] = 0;
  }
}

void blake2cf_export(const void * _st, void * _out) {
  const uint64_t *st = _st;
  uint64_t *out = _out;
  int i;
  for (i = 0; i < 8; i++) {
    *out++ = htole64(*st++);
  }
}

#define ROR64(a, n) (((uint64_t)(a) << (64 - n)) | (((uint64_t)(a) >> n)))

#define G(a, b, c, d) do {                          \
    a = a + b + m[*s++];                            \
    d = ROR64(d ^ a, 32);                           \
    c = c + d;                                      \
    b = ROR64(b ^ c, 24);                           \
    a = a + b + m[*s++];                            \
    d = ROR64(d ^ a, 16);                           \
    c = c + d;                                      \
    b = ROR64(b ^ c, 63);                           \
  } while(0)

#define ROUND do {                                  \
    G(v[ 0], v[ 4], v[ 8], v[12]);                  \
    G(v[ 1], v[ 5], v[ 9], v[13]);                  \
    G(v[ 2], v[ 6], v[10], v[14]);                  \
    G(v[ 3], v[ 7], v[11], v[15]);                  \
    G(v[ 0], v[ 5], v[10], v[15]);                  \
    G(v[ 1], v[ 6], v[11], v[12]);                  \
    G(v[ 2], v[ 7], v[ 8], v[13]);                  \
    G(v[ 3], v[ 4], v[ 9], v[14]);                  \
  } while(0)

void blake2cf_update(void * _st, const void * _block, unsigned long long int t, int final) {
  uint64_t *st = _st;
  const uint64_t *block = _block;
  uint64_t m[16];
  uint64_t v[16];
  const uint8_t *s;
  int i;

  for (i = 0; i < 16; i++) {
    m[i] = le64toh(*block++);
  }

  for (i = 0; i < 8; i++) {
    v[i] = st[i];
    v[8 + i] = iv[i];
  }
  v[12] ^= t;
  if (final) {
    v[14] ^= ~0ULL;
  }

  s = sigma;
  ROUND; ROUND;
  ROUND; ROUND;
  ROUND; ROUND;
  ROUND; ROUND;
  ROUND; ROUND;
  s = sigma;
  ROUND; ROUND;

  for (i = 0; i < 8; i++) {
    st[i] ^= v[i] ^ v[8 + i];
  }
}
