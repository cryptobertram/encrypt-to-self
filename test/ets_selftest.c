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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <alloca.h>
#include <time.h>

#include "../src/sha256ets.h"
#include "../src/sha512ets.h"
#include "../src/blake2ets.h"
#include "../src/ets.h"

#define KEYLEN 16
#define TAGLEN 10
#define ADLEN_MAX 65536
#define MLEN_MAX 65536

uint8_t *key, *ad, *m;

static void test_adlen_mlen(ets_enc ee, ets_dec ed, int adlen, int mlen) {
  uint8_t tag[TAGLEN];
  uint8_t *c, *M;
  int clen = mlen;
  int err, res;

  c = alloca(clen);
  M = alloca(mlen);

  err = (*ee)(KEYLEN, key, adlen, ad, mlen, m, clen, c, TAGLEN, tag);
  if (err) {
    fprintf(stderr, "FATAL: encryption failed\n");
    exit(1);
  }

  memset(M, 0, mlen);
  err = (*ed)(KEYLEN, key, adlen, ad, clen, c, TAGLEN, tag, mlen, M, 1, NULL);
  if (err) {
    fprintf(stderr, "FATAL: decryption failed\n");
    exit(1);
  }
  if (memcmp(m, M, mlen)) {
    fprintf(stderr, "FATAL: wrong message recovered\n");
    exit(1);
  }

  memset(M, 0, mlen);
  err = (*ed)(KEYLEN, key, adlen, ad, clen, c, TAGLEN, tag, mlen, M, 0, &res);
  if (err) {
    fprintf(stderr, "FATAL: decryption failed\n");
    exit(1);
  }
  if (! res) {
    fprintf(stderr, "FATAL: decryption failed\n");
    exit(1);
  }
  if (memcmp(m, M, mlen)) {
    fprintf(stderr, "FATAL: wrong message recovered\n");
    exit(1);
  }

  tag[0] ^= 0xff;

  err = (*ed)(KEYLEN, key, adlen, ad, clen, c, TAGLEN, tag, mlen, M, 1, NULL);
  if (! err) {
    fprintf(stderr, "FATAL: decryption did not fail\n");
    exit(1);
  }

  err = (*ed)(KEYLEN, key, adlen, ad, clen, c, TAGLEN, tag, mlen, M, 0, &res);
  if (err) {
    fprintf(stderr, "FATAL: decryption failed\n");
    exit(1);
  }
  if (res) {
    fprintf(stderr, "FATAL: decryption did not fail\n");
    exit(1);
  }
}

static void test(ets_enc ee, ets_dec ed, int state_size, int block_size) {
  int adlen, mlen;

  /* adlen zero */
  for (mlen = 0 * state_size; mlen < 3 * state_size; mlen++) {
    test_adlen_mlen(ee, ed, 0, mlen);
  }

  /* mlen zero */
  for (adlen = 0 * block_size; adlen < 3 * block_size; adlen++) {
    test_adlen_mlen(ee, ed, adlen, 0);
  }

  /* adlen small, mlen large */
  for (adlen = 0 * block_size; adlen < 3 * block_size; adlen++) {
    for (mlen = 10 * state_size; mlen < 13 * state_size; mlen++) {
      test_adlen_mlen(ee, ed, adlen, mlen);
    }
  }

  /* adlen large, mlen small */
  for (adlen = 10 * block_size; adlen < 13 * block_size; adlen++) {
    for (mlen = 0 * state_size; mlen < 3 * state_size; mlen++) {
      test_adlen_mlen(ee, ed, adlen, mlen);
    }
  }

  /* adlen and mlen roughly same */
  for (adlen = 0 * block_size; adlen < 7 * block_size; adlen++) {
    for (mlen = 0 * state_size; mlen < 7 * state_size; mlen++) {
      test_adlen_mlen(ee, ed, adlen, mlen);
    }
  }
}

static void kat(ets_enc ee, unsigned int csum) {
  uint8_t key[16], ad[5], m[13], c[13], tag[11];
  unsigned int acc;
  int i;

  for (i = 0; i < 16; i++) {
    key[i] = 0 + i;
  }
  for (i = 0; i < 5; i++) {
    ad[i] = 40 + i;
  }
  for (i = 0; i < 13; i++) {
    m[i] = 80 + i;
  }

  (*ee)(16, key, 5, ad, 13, m, 13, c, 11, tag);

  acc = 0;
  for (i = 0; i < 13; i++) {
    acc += c[i];
  }
  for (i = 0; i < 11; i++) {
    acc += tag[i];
  }
  if (acc != csum) {
    fprintf(stderr, "FATAL: wrong checksum: %u != %u\n", acc, csum);
    exit(1);
  }
}

int main(void) {
  int i;

  srand(time(NULL));
  key = alloca(KEYLEN);
  for (i = 0; i < KEYLEN; i++) {
    key[i] = rand() & 0xff;
  }
  ad = alloca(ADLEN_MAX);
  for (i = 0; i < ADLEN_MAX; i++) {
    ad[i] = rand() & 0xff;
  }
  m = alloca(MLEN_MAX);
  for (i = 0; i < MLEN_MAX; i++) {
    m[i] = rand() & 0xff;
  }

  test(sha256ets_enc, sha256ets_dec, 32 /* SHA256CF_STATESIZE */,  64 /* SHA256CF_BLOCKSIZE */);
  test(sha512ets_enc, sha512ets_dec, 64 /* SHA512CF_STATESIZE */, 128 /* SHA512CF_BLOCKSIZE */);
  test(blake2ets_enc, blake2ets_dec, 64 /* BLAKE2CF_STATESIZE */, 128 /* BLAKE2CF_BLOCKSIZE */);

  kat(sha256ets_enc, 3184);
  kat(sha512ets_enc, 3388);
  kat(blake2ets_enc, 2707);

  printf("All tests passed successfully.\n");
  exit(0);
}
