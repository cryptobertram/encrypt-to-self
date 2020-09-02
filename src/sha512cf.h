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

#ifndef SHA512CF_H
#define SHA512CF_H

#define SHA512CF_BLOCKSIZE 128
#define SHA512CF_STATESIZE 64

#define SHA512CF_MEMSTATESIZE 64

void sha512cf_init(void *st);
void sha512cf_clear(void *st);
void sha512cf_export(const void *st, void *out);
void sha512cf_update(void *st, const void *block);
void sha512cf_flip(void *st);

#endif /* SHA512CF_H */
