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

#ifndef BLAKE2CF_H
#define BLAKE2CF_H

#define BLAKE2CF_BLOCKSIZE 128
#define BLAKE2CF_STATESIZE 64

#define BLAKE2CF_MEMSTATESIZE 64

void blake2cf_init(void *st, int klen, int mdlen);
void blake2cf_clear(void *st);
void blake2cf_export(const void *st, void *out);
void blake2cf_update(void *st, const void *block, unsigned long long int t, int final);

#endif /* BLAKE2CF_H */
