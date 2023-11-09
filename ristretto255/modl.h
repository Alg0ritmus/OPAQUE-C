// ******************************************************************
// ----------------- TECHNICAL UNIVERSITY OF KOSICE -----------------
// ---Department of Electronics and Multimedia Telecommunications ---
// -------- FACULTY OF ELECTRICAL ENGINEERING AND INFORMATICS -------
// ------------ THIS CODE IS A PART OF A MASTER'S THESIS ------------
// ------------------------- Master thesis --------------------------
// -----------------Patrik Zelenak & Milos Drutarovsky --------------
// ---------------------------version 0.1.3 -------------------------
// --------------------------- 30-09-2023 ---------------------------
// ******************************************************************

/**
  * This file includes 3 functions taken from crypto library 
  * MonoCypher. We extracted and slightly edited functions
  * that perform modular inverse (arithmetic modulo L).
  * These functions are suitable for creation of other protocols
  * like OPAQUE etc. 
  *
  * Note that mod_l() are build on Barrett reduction which is used
  * later in inverse_mod_l(); which can be suboptimal, even though
  * we reuse temp. space on stack. More efficient way is to use 
  * Montgomery reduction. Due to efficieny we slightly edited 
  * crypto_x25519_inverse() to perform Montgomery reduction. 
  * 
  * NOTE: Extracted and edited code is functional only on 
  * Litle Endian architecture (at least for now)!
**/

#ifndef _MODL_H
#define _MODL_H

// Dependencies
// included definition of types like u8, u32... + FOR macros, etc.
#include "helpers.h" 
#include "utils.h"

void store32_le_buf(u8 *dst, const u32 *src, size_t size);
void mod_l(u8 reduced[BYTES_ELEM_SIZE], const u32 x[16]);
/**
	* Here, we prepared 2 ways of computing modular inverse (mod L).
	* Using Barrett’s reduction: inverse_mod_l; and Montgomery’s
	* reduction crypto_x25519_inverse. You can choose between these
	* two options by commenting/uncommenting the 
	* MONTGOMERY_MODL_INVERSE_FLAG in config.h. We believe that
	* you should be able to select the implementation that best suits
	* your requirements (based on your benchmark).
	* 
	* "Montgomery’s reduction is not efficient for a single modular
	* multiplication, but can be used effectively in computations
	* where many multiplications are performed for given inputs. 
	* Barrett’s reduction is applicable when many reductions
	* are performed with a single modulus."
	* (https://eprint.iacr.org/2014/040.pdf).
**/

#ifdef MONTGOMERY_MODL_INVERSE_FLAG
	void crypto_x25519_inverse(u8 out[BYTES_ELEM_SIZE], const u8 in[BYTES_ELEM_SIZE]);
	#define modl_l_inverse crypto_x25519_inverse
#else
	void inverse_mod_l(u8 out[BYTES_ELEM_SIZE], const u8 in[BYTES_ELEM_SIZE]);
	#define modl_l_inverse inverse_mod_l
#endif

#endif //_MODL_H