// ******************************************************************
// ----------------- TECHNICAL UNIVERSITY OF KOSICE -----------------
// ---Department of Electronics and Multimedia Telecommunications ---
// -------- FACULTY OF ELECTRICAL ENGINEERING AND INFORMATICS -------
// ------------ THIS CODE IS A PART OF A MASTER'S THESIS ------------
// ------------------------- Master thesis --------------------------
// -----------------Patrik Zelenak & Milos Drutarovsky --------------
// ---------------------------version 1.0.1 -------------------------
// --------------------------- 09-03-2024 ---------------------------
// ******************************************************************

/*
 * This file contains original code from 
 * https://github.com/easyaspi314/xxhash-clean. The only 
 * change made was the replacement of malloc, which allocates memory
 *  on the heap, with stack allocation. Changes were made in the 
 * XXH32_createState function and XXH32_freeState accordingly.
*/

/*
 *  xxHash - Fast Hash algorithm
 *  Copyright (C) 2012-2020 Yann Collet
 *  Copyright (C) 2019-2020 Devin Hussey (easyaspi314)
 *
 *  BSD 2-Clause License (http://www.opensource.org/licenses/bsd-license.php)
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are
 *  met:
 *
 *  * Redistributions of source code must retain the above copyright
 *  notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above
 *  copyright notice, this list of conditions and the following disclaimer
 *  in the documentation and/or other materials provided with the
 *  distribution.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *  You can contact the author at :
 *  - xxHash homepage: http://www.xxhash.com
 *  - xxHash source repository : https://github.com/Cyan4973/xxHash */

/* This is a compact, 100% standalone reference XXH32 streaming implementation.
 * Instead of focusing on performance hacks, this focuses on cleanliness,
 * conformance, portability and simplicity.
 *
 * This file aims to be 100% compatible with C90/C++98, with the additional
 * requirement of stdint.h. Unlike the single-run implementation, this uses
 * malloc, free, memset, and memcpy. */

#ifndef _XXHASH_H
#define _XXHASH_H

#include <stddef.h> /* int32_t, NULL */
#include <stdint.h> /* uint8_t, uint32_t */
#include <string.h> /* memset, memcpy */

typedef enum {
    FALSE, TRUE
} XXH_bool;
#ifdef __cplusplus
extern "C" {
#endif

/* Note: This is an opaque structure. The layout differs from the official implementation,
 * it is more compact and orders are different. */
typedef struct XXH32_state_s {
   uint32_t acc1;             /* Our accumulators. */
   uint32_t acc2;
   uint32_t acc3;
   uint32_t acc4;
   uint8_t  temp_buffer[16];   /* Leftover data from a previous update */
   uint32_t temp_buffer_size;  /* how much data is in the temp buffer */
   XXH_bool has_large_len;     /* Whether we had enough to do full rounds. */
   uint32_t total_len_32;      /* The length of the data truncated to 32 bits. */
} XXH32_state_t;

typedef enum {
    XXH_OK = 0,
    XXH_ERROR = 1
} XXH_errorcode;

/*======   Streaming   ======*/
void XXH32_createState(XXH32_state_t * state);
void XXH32_freeState(XXH32_state_t *const state);
void XXH32_copyState(XXH32_state_t *const dest, XXH32_state_t const *const src);

XXH_errorcode XXH32_reset(XXH32_state_t *const state, uint32_t const seed);
XXH_errorcode XXH32_update(XXH32_state_t *const state, void const *const input, int32_t const length);
uint32_t XXH32_digest(XXH32_state_t const *const state);

#ifdef __cplusplus
}
#endif

#endif // _XXHASH_H