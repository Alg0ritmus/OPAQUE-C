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

#include "xxhash.h"

static uint32_t const PRIME32_1 = 0x9E3779B1U;   /* 0b10011110001101110111100110110001 */
static uint32_t const PRIME32_2 = 0x85EBCA77U;   /* 0b10000101111010111100101001110111 */
static uint32_t const PRIME32_3 = 0xC2B2AE3DU;   /* 0b11000010101100101010111000111101 */
static uint32_t const PRIME32_4 = 0x27D4EB2FU;   /* 0b00100111110101001110101100101111 */
static uint32_t const PRIME32_5 = 0x165667B1U;   /* 0b00010110010101100110011110110001 */

/* Rotates value left by amt. */
static uint32_t XXH_rotl32(uint32_t const value, uint32_t const amt)
{
    return (value << (amt % 32)) | (value >> (32 - amt % 32));
}

/* Portably reads a 32-bit little endian integer from data at the given offset. */
static uint32_t XXH_read32(uint8_t const *const data, int32_t const offset)
{
    return (uint32_t) data[offset + 0]
        | ((uint32_t) data[offset + 1] << 8)
        | ((uint32_t) data[offset + 2] << 16)
        | ((uint32_t) data[offset + 3] << 24);
}

/* Mixes input into acc. */
static uint32_t XXH32_round(uint32_t acc, uint32_t const input)
{
    acc += input * PRIME32_2;
    acc  = XXH_rotl32(acc, 13);
    acc *= PRIME32_1;
    return acc;
}

/* Mixes all bits to finalize the hash. */
static uint32_t XXH32_avalanche(uint32_t hash)
{
    hash ^= hash >> 15;
    hash *= PRIME32_2;
    hash ^= hash >> 13;
    hash *= PRIME32_3;
    hash ^= hash >> 16;
    return hash;
}


/* Dynamically allocates XXH32_state_t. It is expected to free this with
 * XXH32_freeState.
 * returns: A pointer to an XXH64_state_t. This may be NULL. */
void XXH32_createState(XXH32_state_t * state)
{
    memset(state, 0, sizeof(XXH32_state_t));
}

/* Frees an XXH64_state_t.
 * state:   The state to free.
 * returns: XXH_OK on success, XXH_ERROR on error. */
void XXH32_freeState(XXH32_state_t * state)
{
    memset(state, 0, sizeof(XXH32_state_t));
}


/* Copies one XXH32_state_t to another.
 * dest:  The state to copy to. It is undefined behavior for dest to overlap with
 *        src.
 * src:   The state to copy from. It is undefined behavior for src to overlap with
 *        dest. */
void XXH32_copyState(XXH32_state_t *const dest, XXH32_state_t const *const src)
{
    memcpy(dest, src, sizeof(XXH32_state_t));
}


/* Resets an XXH64_state_t.
 * state:   The state to reset.
 * seed:    The seed to use.
 * returns: XXH_OK on success, XXH_ERROR on error. */
XXH_errorcode XXH32_reset(XXH32_state_t *const state, uint32_t const seed)
{
    /* Don't write into a null pointer. The official implementation doesn't check
     * for this. */
    if (state == NULL) {
        return XXH_ERROR;
    }

    memset(state, 0, sizeof(XXH32_state_t));

    state->acc1 = seed + PRIME32_1 + PRIME32_2;
    state->acc2 = seed + PRIME32_2;
    state->acc3 = seed + 0;
    state->acc4 = seed - PRIME32_1;
    return XXH_OK;
}

/* The XXH32 hash function update loop.
 * state:   The current state. It is undefined behavior to overlap with input.
 * input:   The data to hash. It is undefined behavior to overlap with state.
 * length:  The length of input. It is undefined behavior to have length larger than the
 *          capacity of input.
 * returns: XXH_OK on success, XXH_ERROR on failure. */
XXH_errorcode XXH32_update(XXH32_state_t *const state, void const *const input, int32_t const length)
{
    uint8_t const *const data = (uint8_t const *) input;
    int32_t remaining;
    int32_t offset = 0;

    /* Don't dereference a null pointer. The reference implementation notably doesn't
     * check for this by default. */
    if (state == NULL || input == NULL) {
        return XXH_ERROR;
    }

    state->total_len_32 += (uint32_t) length;

    if (state->has_large_len == FALSE && (length >= 16 || state->total_len_32 >= 16)) {
        state->has_large_len = TRUE;
    }

    if (state->temp_buffer_size + length < 16)  {
        /* We don't have a full buffer, so we just copy the data over and return. */
        memcpy(&state->temp_buffer[state->temp_buffer_size], input, length);
        state->temp_buffer_size += (uint32_t) length;
        return XXH_OK;
    }

    remaining = state->temp_buffer_size + length;

     while (remaining >= 16) {
        /* fill up our temp buffer */
        memcpy(&state->temp_buffer[state->temp_buffer_size], &data[offset], 16 - state->temp_buffer_size);

        /* do our rounds */
        state->acc1 = XXH32_round(state->acc1, XXH_read32(state->temp_buffer, 0));
        state->acc2 = XXH32_round(state->acc2, XXH_read32(state->temp_buffer, 4));
        state->acc3 = XXH32_round(state->acc3, XXH_read32(state->temp_buffer, 8));
        state->acc4 = XXH32_round(state->acc4, XXH_read32(state->temp_buffer, 12));

        /* done with the rounds */
        offset += 16 - state->temp_buffer_size;
        remaining -= 16;
        state->temp_buffer_size = 0;
    }

    if (remaining != 0) {
        memcpy(state->temp_buffer, &data[offset], remaining);
        state->temp_buffer_size = (uint32_t) remaining;
    }

    return XXH_OK;
}

/* Finalizes an XXH32_state_t and returns the seed.
 * state:   The state to finalize. This is not modified.
 * returns: The calculated 32-bit hash. */
uint32_t XXH32_digest(XXH32_state_t const *const state)
{
    uint32_t hash;
    uint32_t remaining = state->temp_buffer_size;
    uint32_t offset = 0;

    if (state->has_large_len == TRUE) {
        hash = XXH_rotl32(state->acc1, 1)
             + XXH_rotl32(state->acc2, 7)
             + XXH_rotl32(state->acc3, 12)
             + XXH_rotl32(state->acc4, 18);
    } else {
        /* Not enough data for the main loop, put something in there instead. */
        hash = state->acc3 /* will be seed because of the + 0 */ + PRIME32_5;
    }

    hash += state->total_len_32;

    /* Process the remaining data. */
    while (remaining >= 4) {
        hash += XXH_read32(state->temp_buffer, offset) * PRIME32_3;
        hash  = XXH_rotl32(hash, 17);
        hash *= PRIME32_4;
        offset += 4;
        remaining -= 4;
    }

    while (remaining != 0) {
        hash += (uint32_t) state->temp_buffer[offset] * PRIME32_5;
        hash  = XXH_rotl32(hash, 11);
        hash *= PRIME32_1;
        --remaining;
        ++offset;
    }

    return XXH32_avalanche(hash);
}


