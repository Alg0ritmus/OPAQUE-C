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
  * This file is core of our ristretto255 implementation. It is more
  * efficient version of our equivalent TweetNaCl version 
  * of ristretto255 (https://github.com/Alg0ritmus/textbook_ristretto255).
  * This file includes all necessary functions for creation of other
  * protocols that use  eliptic curve Curve25519. 
  *
  * Ristretto255 is a cryptographic construction designed for 
  * efficient and secure elliptic curve cryptography (ECC) 
  * operations. It is based on the Curve25519 elliptic curve,
  * which is a widely used curve in modern cryptography
  * due to its strong security properties and efficient performance.
  *
  * Curve25519, the underlying elliptic curve, has a cofactor of 8,
  * meaning its order is eight times a prime number. This cofactor 
  * introduces the possibility of small subgroup attacks because not
  * all points on the curve are in the main subgroup. The cofactor
  * is a factor by which the order of the elliptic curve group is
  * divisible. In elliptic curve cryptography, it's important to work
  * with points that are on the main subgroup of the curve, as points
  * on small subgroups can introduce vulnerabilities.
  *
  * Ristretto255 addresses this issue by providing a way to map 
  * points from the Curve25519 curve to a unique representative point
  * in a group that eliminates the cofactor-related vulnerabilities.
  * By doing so, it ensures that all points in its representation 
  * belong to the main subgroup, making it resistant to small 
  * subgroup attacks and other potential security issues associated
  * with the cofactor. This mapping is carefully designed to maintain
  * compatibility with Curve25519's arithmetic operations while 
  * addressing the cofactor problem, thus providing a safer
  * and more predictable foundation for cryptographic protocols.
  *
  * In our representation we used Cyclone, a crypto library,
  * that internaly works with 8-word elements. This is why we chose
  * field_elem (our internal representation of GF(2*255-19) 
  * field element) as 8-word elements. We chose Cyclone crypto library
  * because of its advantages, such as compactness and speed,
  * elimination of I/O conversion. In other words, we do not need to
  * perform any conversion, such as pack/unpack or from_bytes/to_bytes
  * as required by other libraries like TweetNaCl or MonoCypher. Note
  * that we are using pack/unpack terminology just for copying data.
  * Most of the functions used from Cyclone are identical with 
  * original code. In fact we just extract and rename all necessary
  * functions.
  *
  * Results from our speed measurements have shown that Cyclone is
  * approximately 5 times faster than TweetNaCl (packing/unpacking
  * not included). Additionally, while MonoCypher is slightly faster
  * (about 1.5 times) than Cyclone, there are highly efficient 
  * implementations written in assembly language that outperform
  * any C implementations. These are particularly suitable for
  * embedded MCUs like the ARM Cortex-M4. This is one of the reasons
  * why we chose Cyclone.
  * Note that measurements were performed on an STM32 MCU with
  * a Cortex-M3 core. 
  * 
  * Besides Cyclone we also implemented necessary functions to 
  * perform scalar multiplication of ristretto255 point.
  * Ristretto255 point has its own representation (see `helpers.h`),
  * that uses extended Edwards point form. Internally, a Ristretto
  * point is represented by an extended Edwards point. 
  * Two extended Edwards points P,Q may represent the same Ristretto
  * point, in the same way that different projective X,Y,Z,T 
  * coordinates may represent the same extended Edwards point.
  * Group operations on Ristretto points are carried out with no 
  * overhead by performing the operations on the representative
  * Edwards points. For example ristretto255_point_addition() performs
  * addition of ristretto255 points, which impl. was largely inspired
  * by TweetNaCl crypto library.
**/


#ifndef _RISTRETTO255_H
#define _RISTRETTO255_H

#include "utils.h"

int ristretto255_decode(ristretto255_point *ristretto_out, const u8 bytes_in[BYTES_ELEM_SIZE]);
int ristretto255_encode(u8 bytes_out[BYTES_ELEM_SIZE], const ristretto255_point *ristretto_in);
int hash_to_group(u8 bytes_out[BYTES_ELEM_SIZE], const u8 bytes_in[HASH_BYTES_SIZE]);
void ristretto255_scalarmult(ristretto255_point* p, ristretto255_point* q,const u8 *s);
void ristretto255_point_addition(ristretto255_point* r,const ristretto255_point* p,const ristretto255_point* q);
int bytes_eq_32( const u8 a[BYTES_ELEM_SIZE],  const u8 b[BYTES_ELEM_SIZE]);
void fneg(field_elem out, field_elem in);
int is_neg(field_elem in);
int is_neg_bytes(const u8 in[BYTES_ELEM_SIZE]);
void fabsolute(field_elem out, field_elem in);
void pack(u8* uint8Array,const u32* uint32ArrayIn);
void unpack(u32* uint32Array, const u8* uint8Array);

#endif //_RISTRETTO255_H