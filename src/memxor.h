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

#ifndef MEMXOR_H
#define MEMXOR_H

#define memxor3(_dst, _srcA, _srcB, _num) do {                          \
    uint64_t *dst64; const uint64_t *src64A, *src64B;                   \
    uint8_t *dst8; const uint8_t *src8A, *src8B;                        \
    size_t num = (_num);                                                \
    dst64 = (uint64_t *)(_dst);                                         \
    src64A = (const uint64_t *)(_srcA);                                 \
    src64B = (const uint64_t *)(_srcB);                                 \
    if (((unsigned long)dst64 | (unsigned long)src64A | (unsigned long)src64B) % 8 == 0) { \
      for ( ; num >= 8; num -= 8) {                                     \
        *dst64++ = *src64A++ ^ *src64B++;                               \
      }                                                                 \
    }                                                                   \
    dst8 = (uint8_t *)(dst64);                                          \
    src8A = (const uint8_t *)(src64A);                                  \
    src8B = (const uint8_t *)(src64B);                                  \
    while (num--) {                                                     \
      *dst8++ = *src8A++ ^ *src8B++;                                    \
    }                                                                   \
  } while (0)

#define memxor2(_dst, _src, _num) do {                                  \
    uint64_t *dst64; const uint64_t *src64;                             \
    uint8_t *dst8; const uint8_t *src8;                                 \
    size_t num = (_num);                                                \
    dst64 = (uint64_t *)(_dst);                                         \
    src64 = (const uint64_t *)(_src);                                   \
    if (((unsigned long)dst64 | (unsigned long)src64) % 8 == 0) {       \
      for ( ; num >= 8; num -= 8) {                                     \
        *dst64++ ^= *src64++;                                           \
      }                                                                 \
    }                                                                   \
    dst8 = (uint8_t *)(dst64);                                          \
    src8 = (const uint8_t *)(src64);                                    \
    while (num--) {                                                     \
      *dst8++ ^= *src8++;                                               \
    }                                                                   \
  } while (0)

#endif /* MEMXOR_H */
