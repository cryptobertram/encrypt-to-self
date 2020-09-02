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
#include <string.h>
#include <stdio.h>
#include <alloca.h>
#include <time.h>

/* use BLAKE2 based code, other options possible */
#include "src/blake2ets.h"
#include "src/ets.h"

#define KEYLEN 32 /* 256 bit, other options possible */
#define TAGLEN 16 /* 128 bit, other options possible */

#define TEST_AD "an arbitrary associated data string"
#define TEST_MSG "an arbitrary message"

int main(void) {
  char key[KEYLEN], tag[TAGLEN], *c, *m;
  size_t adlen, mlen, clen;
  int err, is_valid;
  int i;

  ets_enc ets_enc = blake2ets_enc;
  ets_dec ets_dec = blake2ets_dec;

  /* note that encrypt-to-self is a one-time primitive, i.e., each key may be used for at most one encryption. */

  /* generate a fresh key; this method is not safe and in production code should be replaced by a different method */
  srand(time(NULL));
  for (i = 0; i < KEYLEN; i++) {
    key[i] = rand() & 0xff;
  }

  adlen = strlen(TEST_AD);
  mlen = strlen(TEST_MSG);
  clen = mlen;

  /* reserve space for ciphertext */
  c = alloca(clen);

  /* encryption; the ciphertext is stored in c, the tag is stored in tag */
  err = ets_enc(KEYLEN, key, adlen, TEST_AD, mlen, TEST_MSG, clen, c, TAGLEN, tag);
  if (err) {
    fprintf(stderr, "FATAL: encryption failed\n");
    exit(1);
  }

  /* reserve space for recovered message */
  m = alloca(mlen);

  /* decryption option 1; indicate tag invalidity via the return value */
  err = ets_dec(KEYLEN, key, adlen, TEST_AD, clen, c, TAGLEN, tag, mlen, m, 1, NULL);
  if (err) {
    fprintf(stderr, "FATAL: decryption failed (possibly because of invalid tag)\n");
    exit(1);
  }

  /* assert that encrypted and decrypted messages are the same */
  if (memcmp(m, TEST_MSG, mlen)) {
    fprintf(stderr, "FATAL: wrong message recovered\n");
    exit(1);
  }

  /* decryption option 2; indicate tag invalidity via flag */
  err = ets_dec(KEYLEN, key, adlen, TEST_AD, clen, c, TAGLEN, tag, mlen, m, 0, &is_valid);
  if (err) {
    fprintf(stderr, "FATAL: decryption failed\n");
    exit(1);
  }
  if (! is_valid) {
    fprintf(stderr, "FATAL: invalid tag\n");
    exit(1);
  }

  /* assert that encrypted and decrypted messages are the same */
  if (memcmp(m, TEST_MSG, mlen)) {
    fprintf(stderr, "FATAL: wrong message recovered\n");
    exit(1);
  }

  printf("Message first encrypted and then successfully recovered.\n");
  exit(0);
}
