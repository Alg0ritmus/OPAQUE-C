// ******************************************************************
// ----------------- TECHNICAL UNIVERSITY OF KOSICE -----------------
// ---Department of Electronics and Multimedia Telecommunications ---
// -------- FACULTY OF ELECTRICAL ENGINEERING AND INFORMATICS -------
// ------------ THIS CODE IS A PART OF A MASTER'S THESIS ------------
// ------------------------- Master thesis --------------------------
// -----------------Patrik Zelenak & Milos Drutarovsky --------------
// ---------------------------version T.T.5 -------------------------
// --------------------------- 12-02-2024 ---------------------------
// ******************************************************************

/**
  * This file contains PRNG taken from:
  * https://rosettacode.org/wiki/Linear_congruential_generator#C
  * 
  * A rand_32_bytes is a function that we use to generate a 
  * random 32-byte value. We also changed srand() to s_rand()
  *  in naming, and we made it available from external files
  *  by removing the static keyword.
**/

#include "prng.h"

static int32_t rseed = 0; // seed can be changed externally using s_rand()

void s_rand(int32_t x)
{
	rseed = x;
}

#ifndef MS_RAND
#define RAND_MAX ((1U << 31) - 1)

static inline int32_t rand()
{
	return rseed = (rseed * 1103515245 + 12345) & RAND_MAX;
}

#else /* MS rand */

#define RAND_MAX_32 ((1U << 31) - 1)

static inline int32_t rand()
{
	return (rseed = (rseed * 214013 + 2531011) & RAND_MAX_32) >> 16;
}

#endif/* MS_RAND */



void rand_32_bytes(u8 out[32]){
    for (u8 i = 0; i < 32; i++){
        out[i] = (rand() >> 16) & 0xFF;
    }
}


// generate random value < L in constant time
// inspired by: https://github.com/facebook/ristretto255-js/blob/main/src/ristretto255.js
// NOTE that this approach is potentially faster than approach "generate random scalar 
// and reduce (mod L)"
void rand_32_bytes_lower_thanL(u8 r[32]){
    // using static just to store value outside stack
    static const  u8 L[32] = { // L - 2, where L = 2**252+27742317777372353535851937790883648493
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    };
    u8 c;

    while (1) {
        rand_32_bytes(r); 
        r[31] &= 0x1f;

        // Constant-time check for r < L, if so break and return r
        u8 i = 32;
        c = 0;
        u8 n = 1;

        while (i != 0) {
            i--;
            c |= ((r[i] - L[i]) >> 8) & n;
            n &= ((r[i] ^ L[i]) - 1) >> 8;
        }

        if (c != 0) {
            // Just break the loop
            return;
        }
    }
}