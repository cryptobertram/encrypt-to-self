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

#ifndef BLAKE2ETS_H
#define BLAKE2ETS_H

/*
  Note that encrypt-to-self is a one-time primitive, i.e., each key may be used for at most one encryption.

  Further usage instructions:

  - values klen, adlen, mlen, clen, taglen are indicated in bytes

  - admissible values for klen range from 16 bytes (128 bit) to 64 bytes (512 bits), in steps of 8 bytes (64 bits);
    concretely, klen has to be one of 16,24,32,40,48,56,64 bytes (128,192,256,320,384,448,512 bits)

  - admissible values for taglen range from 10 bytes (80 bits) to 64 bytes (512 bits), in steps of 1 byte (8 bits)

  - values mlen and clen have to match for each invocation

  - if fail_if_invalid is true and is_valid == NULL: blake2ets_dec flags invalid ciphertexts by returning -1;
    if fail_if_invalid is false and is_valid != NULL: blake2ets_dec stores validity indicator in *is_valid and returns 0.
*/

int blake2ets_enc(size_t klen, const void *k, size_t adlen, const void *ad, size_t mlen, const void *m, size_t clen, void *c, size_t taglen, void *tag);
int blake2ets_dec(size_t klen, const void *k, size_t adlen, const void *ad, size_t clen, const void *c, size_t taglen, const void *tag, size_t mlen, void *m, int fail_if_invalid, int *is_valid);

#endif /* BLAKE2ETS_H */
