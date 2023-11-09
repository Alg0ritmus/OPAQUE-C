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
  * This file contains the structure of 'field_elem,'
  * which serves as the internal representation of field elements 
  * in GF(2^255-19).
  * In our code, 'field_elem' represents a array of eight words,
  * each with a length of 'uint32_t.' This structure is well-suited 
  * for our representation of 'ristretto255' bcs. we do not need to
  * perform packing/unpacking to obtain the internal representation
  * required for internal calculations, unlike other libraries.
  *
  * File also includes repr. of ristretto255_point,
  * which is point that uses twisted endward's curve,
  * extended coordinate representation (X, Y, Z, T).
  *
  * Last but not least, the file provides redefined types,
  * length constants, and macros used throughout the entire codebase.
**/

#ifndef _HELPERS_H
#define _HELPERS_H

#include <stdio.h>
#include <stdint.h>
#include "config.h"

// In elliptic curve cryptography, computations are performed
// within a finite field (field_elem), and the FIELED_ELEM_SIZE (u32x8) 
// macro defines the size of an element in that field.
// 
// Note that while FIELED_ELEM_SIZE defines the byte size of the
// internal field_elem (finite field element), the BYTES_ELEM_SIZE
// defines  the size of the external byte element (common u8x32 
// little-endian order element). 
//
// The macro HASH_BYTES_SIZE defines the size of the hash
// digest (u8x64), which is 512 bits, suitable for hash functions
// like SHA-512. It's worth noting that Ristretto255 defines
// hash_to_group, which takes a 512-bit hash digest and maps
// it into a ristretto255_point.

#define FIELED_ELEM_SIZE 8 
#define BYTES_ELEM_SIZE 32 
#define HASH_BYTES_SIZE 2*BYTES_ELEM_SIZE 

typedef uint8_t  u8;
typedef uint32_t u32;
typedef uint64_t u64;


// cyclone represantation of field_element
typedef u32 field_elem[FIELED_ELEM_SIZE];

typedef struct ge_point25519 {
    field_elem x,y,z,t;
} ristretto255_point;


// Here we implemented some macros to make
// code more readable. 
/*-----------------------------------*/

#define FOR_T(i, start, end) for (i = (start); i < (end); i++)
#define FOR(i, start, end)         FOR_T(i, start, end)
#define COPY(i, dst, src, size)    FOR(i, 0, size) (dst)[i] = (src)[i]
#define ZERO(i, buf, size)         FOR(i, 0, size) (buf)[i] = 0

#endif //_HELPERS_H