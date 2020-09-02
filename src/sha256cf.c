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

#define _DEFAULT_SOURCE /* activates  htobe32  and  be32toh  from endian.h */
#include <stdint.h>
#include <endian.h>
#include "sha256cf.h"

_Static_assert(sizeof(uint32_t[8]) == SHA256CF_MEMSTATESIZE, "SHA256CF_MEMSTATESIZE has wrong value!");

static const uint32_t k[64] = {
  0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
  0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
  0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
  0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
  0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
  0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
  0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
  0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
  0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
  0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
  0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
  0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
  0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
  0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
  0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
  0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL,
};

static const uint32_t iv[8] = {
  0x6a09e667UL, 0xbb67ae85UL, 0x3c6ef372UL, 0xa54ff53aUL,
  0x510e527fUL, 0x9b05688cUL, 0x1f83d9abUL, 0x5be0cd19UL,
};

void sha256cf_init(void * _st) {
  uint32_t *st = _st;
  int i;
  for (i = 0; i < 8; i++) {
    st[i] = iv[i];
  }
}

void sha256cf_clear(void * _st) {
  uint32_t *st = _st;
  int i;
  for (i = 0; i < 8; i++) {
    st[i] = 0;
  }
}

void sha256cf_export(const void * _st, void * _out) {
  const uint32_t *st = _st;
  uint32_t *out = _out;
  int i;
  for (i = 0; i < 8; i++) {
    *out++ = htobe32(*st++);
  }
}

#define ROR32(a, n) (((uint32_t)(a) << (32 - n)) | (((uint32_t)(a) >> n)))
#define Sigma0(x) (ROR32((x), 2) ^ ROR32((x), 13) ^ ROR32((x), 22))
#define Sigma1(x) (ROR32((x), 6) ^ ROR32((x), 11) ^ ROR32((x), 25))
#define sigma0(x) (ROR32((x), 7) ^ ROR32((x), 18) ^ ((x) >> 3))
#define sigma1(x) (ROR32((x), 17) ^ ROR32((x), 19) ^ ((x) >> 10))
#define Ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

void sha256cf_update(void * _st, const void * _block) {
  uint32_t *st = _st;
  const uint32_t *block = _block;
  uint32_t a, b, c, d, e, f, g, h;
  uint32_t w[16];
  uint32_t s0, s1, temp1, temp2;
  int i;

  a = st[0];
  b = st[1];
  c = st[2];
  d = st[3];
  e = st[4];
  f = st[5];
  g = st[6];
  h = st[7];

  for (i = 0; i < 16; i++) {
    w[i] = be32toh(*block++);
    temp1 = h + Sigma1(e) + Ch(e, f, g) + k[i] + w[i];
    temp2 = Sigma0(a) + Maj(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  for (; i < 64; i++) {
    s0 = w[(i - 15 + 16) & 0x0f];
    s0 = sigma0(s0);
    s1 = w[(i - 2 + 16) & 0x0f];
    s1 = sigma1(s1);
    w[i & 0x0f] += s0 + w[(i - 7 + 16) & 0x0f] + s1;
    temp1 = h + Sigma1(e) + Ch(e, f, g) + k[i] + w[i & 0x0f];
    temp2 = Sigma0(a) + Maj(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  st[0] += a;
  st[1] += b;
  st[2] += c;
  st[3] += d;
  st[4] += e;
  st[5] += f;
  st[6] += g;
  st[7] += h;
}

void sha256cf_flip(void * _st) {
  uint32_t *st = _st;
  int i;
  for (i = 0; i < 8; i++) {
    st[i] ^= 0xa5a5a5a5UL;
  }
}
