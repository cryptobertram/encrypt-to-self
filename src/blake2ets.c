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
#include <string.h>

#include "blake2cf.h"
#include "blake2ets.h"
#include "memxor.h"

#define C BLAKE2CF_STATESIZE /* 64 */
#define D BLAKE2CF_BLOCKSIZE /* 128 */

#define assert(C) do { ; } while (! (C)) /* poor man's assert */

_Static_assert(C <= D && C <= 256, "required by mode");

/* round up to next multiple of 8 (for copy efficiency on 64-bit machines) */
#define RUP_8(x) (((x) + 7) & ~0x07)

#define MAV 16 /* memory alignment value (for even faster copies) */
_Static_assert((MAV & (MAV - 1)) == 0, "memory alignment value not a power of two");

#define RUP_MAV(x) (((x) + MAV - 1) & ~(MAV - 1)) /* round up to next multiple of MAV */

_Static_assert(C == RUP_MAV(C) && D == RUP_MAV(D), "compression function shall work well with memory-aligned data");

#define CHECK_PARAMS_ENCDEC(klen, adlen, mlen, clen, taglen)            \
  (                                                                     \
   ((klen) >= 128 / 8 && (klen) <= (D - C) && (klen) == RUP_8(klen))    \
   &&                                                                   \
   ((klen) <= 64) /* maximum blake2cf key length */                     \
   &&                                                                   \
   ((clen) == (mlen))                                                   \
   &&                                                                   \
   ((taglen) >= 80 / 8 && (taglen) <= C)                                \
  )

#define AD_FINALIZER 0x80

#define LOAD_AD_INTO_BLOCK(_len) do {                                   \
    /* assert(! ad_padded); */                                          \
    size_t len = (_len);                                                \
    if (adlen >= len) {                                                 \
      memcpy(block, ad, len);                                           \
      ad += len, adlen -= len;                                          \
    }                                                                   \
    else /* if (0 <= adlen < len) */ {                                  \
      memcpy(block, ad, adlen);                                         \
      block[adlen] = AD_FINALIZER;                                      \
      memset(block + adlen + 1, 0, len - adlen - 1);                    \
      /* ad += adlen, adlen = 0; */                                     \
      ad_padded = 1;                                                    \
    }                                                                   \
  } while (0)

int blake2ets_enc(size_t klen, const void *k, size_t adlen, const void * _ad, size_t mlen, const void * _m, size_t clen, void * _c, size_t taglen, void *tag) {
  const uint8_t *ad = _ad;
  const uint8_t *m = _m;
  uint8_t *c = _c;
  uint8_t st[BLAKE2CF_MEMSTATESIZE];
  uint8_t block[D], buf[C];
  unsigned long long int t = 0;
  int ad_padded = 0;
  int m_padded = 0;
  int default_ad_block = 0; /* (default_ad_block == 1) ==> (block[0..D-C-1] == zero-padded key) */
  size_t mlen_rup;

  if (! CHECK_PARAMS_ENCDEC(klen, adlen, mlen, clen, taglen)) {
    return -1;
  }

  if (mlen == 0) {
    m_padded = 1;
  }

  /* first block */
  LOAD_AD_INTO_BLOCK(D);
  memxor2(block, k, klen);

  blake2cf_init(st, klen, taglen);

  /* bulk message processing */
  while (mlen >= C) {
    blake2cf_update(st, block, t++, 0);

    if (! ad_padded) {
      LOAD_AD_INTO_BLOCK(D - C);
      memxor2(block, k, klen);
    }
    else /* if (ad_padded) */ {
      if (! default_ad_block) {
        memcpy(block, k, klen);
        memset(block + klen, 0, D - C - klen);
        default_ad_block = 1;
      }
    }

    blake2cf_export(st, buf);
    memxor3(c, m, buf, C);
    memcpy(block + D - C, m, C);
    c += C, m += C, mlen -= C;
  }

  /* in case a partial message block remains */
  if (0 < mlen /* && mlen < C */) {
    blake2cf_update(st, block, t++, 0);

    mlen_rup = RUP_MAV(mlen + 1); /* by mlen < C and C == RUP_MAV(C): mlen_rup <= C */

    if (! ad_padded) {
      LOAD_AD_INTO_BLOCK(D - mlen_rup);
      memxor2(block, k, klen);
    }
    else /* if (ad_padded) */ {
      if (default_ad_block) {
        memset(block + D - C, 0, C - mlen_rup);
      }
      else /* if (! default_ad_block) */ {
        memcpy(block, k, klen);
        memset(block + klen, 0, D - mlen_rup - klen);
        /* default_ad_block = 1; */
      }
    }

    blake2cf_export(st, buf);
    memxor3(c, m, buf, mlen);
    /* c += mlen; */

    memcpy(block + D - mlen_rup, m, mlen);
    memset(block + D - mlen_rup + mlen, 0, mlen_rup - mlen - 1);
    block[D - 1] = mlen; /* requires C <= 256 (bytes) */
    /* m += mlen, mlen = 0; */
    m_padded = 1;
  }

  if (! ad_padded && adlen > 0) {
    blake2cf_update(st, block, t++, 1);

    while (adlen > D) {
      blake2cf_update(st, ad, t++, 0);
      ad += D, adlen -= D;
    }
    /* assert(0 < adlen && adlen <= D); */
    LOAD_AD_INTO_BLOCK(D);
    /* assert(ad_padded || (! ad_padded && adlen == 0)); */
  }

  if (m_padded) {
    blake2cf_update(st, block, t++, 1);
  }
  else {
    blake2cf_update(st, block, t++, 0);
  }

  blake2cf_export(st, buf);
  /* blake2cf_clear(st); */

  if (ad_padded) {
    unsigned int i;
    for (i = 0; i < taglen; i++) {
      buf[i] ^= 0xa5;
    }
  }

  memcpy(tag, buf, taglen);

  return 0;
}

int blake2ets_dec(size_t klen, const void *k, size_t adlen, const void * _ad, size_t clen, const void * _c, size_t taglen, const void *tag, size_t mlen, void * _m, int fail_if_invalid, int *is_valid) {
  const uint8_t *ad = _ad;
  const uint8_t *c = _c;
  uint8_t *m = _m;
  uint8_t st[BLAKE2CF_MEMSTATESIZE];
  uint8_t block[D], buf[C];
  unsigned long long int t = 0;
  int ad_padded = 0;
  int m_padded = 0;
  int default_ad_block = 0; /* (default_ad_block == 1) ==> (block[0..D-C-1] == zero-padded key) */
  size_t mlen_rup;
  int valid;

  if (! CHECK_PARAMS_ENCDEC(klen, adlen, mlen, clen, taglen)) {
    return -1;
  }

  if (mlen == 0) {
    m_padded = 1;
  }

  /* first block */
  LOAD_AD_INTO_BLOCK(D);
  memxor2(block, k, klen);

  blake2cf_init(st, klen, taglen);

  /* bulk ciphertext processing */
  while (mlen >= C) {
    blake2cf_update(st, block, t++, 0);

    if (! ad_padded) {
      LOAD_AD_INTO_BLOCK(D - C);
      memxor2(block, k, klen);
    }
    else /* if (ad_padded) */ {
      if (! default_ad_block) {
        memcpy(block, k, klen);
        memset(block + klen, 0, D - C - klen);
        default_ad_block = 1;
      }
    }

    blake2cf_export(st, buf);
    memxor3(m, c, buf, C);
    memcpy(block + D - C, m, C);
    c += C, m += C, mlen -= C;
  }

  /* in case a partial ciphertext block remains */
  if (0 < mlen /* && mlen < C */) {
    blake2cf_update(st, block, t++, 0);

    mlen_rup = RUP_MAV(mlen + 1); /* by mlen < C and C == RUP_MAV(C): mlen_rup <= C */

    if (! ad_padded) {
      LOAD_AD_INTO_BLOCK(D - mlen_rup);
      memxor2(block, k, klen);
    }
    else /* if (ad_padded) */ {
      if (default_ad_block) {
        memset(block + D - C, 0, C - mlen_rup);
      }
      else /* if (! default_ad_block) */ {
        memcpy(block, k, klen);
        memset(block + klen, 0, D - mlen_rup - klen);
        /* default_ad_block = 1; */
      }
    }

    blake2cf_export(st, buf);
    memxor3(m, c, buf, mlen);
    /* c += mlen; */

    memcpy(block + D - mlen_rup, m, mlen);
    memset(block + D - mlen_rup + mlen, 0, mlen_rup - mlen - 1);
    block[D - 1] = mlen; /* requires C <= 256 (bytes) */
    /* m += mlen, mlen = 0; */
    m_padded = 1;
  }

  if (! ad_padded && adlen > 0) {
    blake2cf_update(st, block, t++, 1);

    while (adlen > D) {
      blake2cf_update(st, ad, t++, 0);
      ad += D, adlen -= D;
    }
    /* assert(0 < adlen && adlen <= D); */
    LOAD_AD_INTO_BLOCK(D);
    /* assert(ad_padded || (! ad_padded && adlen == 0)); */
  }

  if (m_padded) {
    blake2cf_update(st, block, t++, 1);
  }
  else {
    blake2cf_update(st, block, t++, 0);
  }

  blake2cf_export(st, buf);
  /* blake2cf_clear(st); */

  if (ad_padded) {
    unsigned int i;
    for (i = 0; i < taglen; i++) {
      buf[i] ^= 0xa5;
    }
  }

  valid = ! memcmp(buf, tag, taglen); /* constant-time comparison not necessary */

  if (fail_if_invalid) {
    assert(is_valid == NULL);
    if (! valid) {
      return -1;
    }
  }
  else /* if (! fail_if_invalid) */ {
    assert(is_valid != NULL);
    *is_valid = valid;
  }

  return 0;
}
