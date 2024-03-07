// ******************************************************************
// ----------------- TECHNICAL UNIVERSITY OF KOSICE -----------------
// ---Department of Electronics and Multimedia Telecommunications ---
// -------- FACULTY OF ELECTRICAL ENGINEERING AND INFORMATICS -------
// ------------ THIS CODE IS A PART OF A MASTER'S THESIS ------------
// ------------------------- Master thesis --------------------------
// -----------------Patrik Zelenak & Milos Drutarovsky --------------
// ---------------------------version 1.0.0 -------------------------
// --------------------------- 07-03-2024 ---------------------------
// ******************************************************************

/**
  * This file contains PRNG taken from:
  * https://rosettacode.org/wiki/Linear_congruential_generator#C
  * 
  * A rand_32_bytes is a function that we use to generate a 
  * random 32-byte value.
**/


#ifndef _PRNG_H
#define _PRNG_H

#include <stdio.h>
#include "helpers.h"

void rand_32_bytes(u8 out[32]);
void s_rand(int32_t x);
void rand_32_bytes_lower_thanL(u8 r[32]);


#endif //_PRNG_H