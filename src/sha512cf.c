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

#define _DEFAULT_SOURCE /* activates  htobe64  and  be64toh  from endian.h */
#include <stdint.h>
#include <endian.h>
#include "sha512cf.h"

_Static_assert(sizeof(uint64_t[8]) == SHA512CF_MEMSTATESIZE, "SHA512CF_MEMSTATESIZE has wrong value!");

static const uint64_t k[80] = {
  0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
  0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
  0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
  0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
  0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
  0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
  0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
  0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
  0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
  0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
  0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
  0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
  0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
  0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
  0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
  0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
  0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
  0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
  0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
  0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

static const uint64_t iv[8] = {
  0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
  0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
};

void sha512cf_init(void * _st) {
  uint64_t *st = _st;
  int i;
  for (i = 0; i < 8; i++) {
    st[i] = iv[i];
  }
}

void sha512cf_clear(void * _st) {
  uint64_t *st = _st;
  int i;
  for (i = 0; i < 8; i++) {
    st[i] = 0;
  }
}

void sha512cf_export(const void * _st, void * _out) {
  const uint64_t *st = _st;
  uint64_t *out = _out;
  int i;
  for (i = 0; i < 8; i++) {
    *out++ = htobe64(*st++);
  }
}

#define ROR64(a, n) (((uint64_t)(a) << (64 - n)) | (((uint64_t)(a) >> n)))
#define Sigma0(x) (ROR64((x), 28) ^ ROR64((x), 34) ^ ROR64((x), 39))
#define Sigma1(x) (ROR64((x), 14) ^ ROR64((x), 18) ^ ROR64((x), 41))
#define sigma0(x) (ROR64((x), 1) ^ ROR64((x), 8) ^ ((x) >> 7))
#define sigma1(x) (ROR64((x), 19) ^ ROR64((x), 61) ^ ((x) >> 6))
#define Ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

void sha512cf_update(void * _st, const void * _block) {
  uint64_t *st = _st;
  const uint64_t *block = _block;
  uint64_t a, b, c, d, e, f, g, h;
  uint64_t w[16];
  uint64_t s0, s1, temp1, temp2;
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
    w[i] = be64toh(*block++);
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

  for (; i < 80; i++) {
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

void sha512cf_flip(void * _st) {
  uint64_t *st = _st;
  int i;
  for (i = 0; i < 8; i++) {
    st[i] ^= 0xa5a5a5a5a5a5a5a5ULL;
  }
}
