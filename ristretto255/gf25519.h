// ******************************************************************
// ----------------- TECHNICAL UNIVERSITY OF KOSICE -----------------
// ---Department of Electronics and Multimedia Telecommunications ---
// -------- FACULTY OF ELECTRICAL ENGINEERING AND INFORMATICS -------
// ------------ THIS CODE IS A PART OF A MASTER'S THESIS ------------
// ------------------------- Master thesis --------------------------
// -----------------Patrik Zelenak & Milos Drutarovsky --------------
// ---------------------------version T.T.5 -------------------------
// --------------------------- 05-02-2024 ---------------------------
// ******************************************************************

/**
  * This file represents an excerpt of code from the cryptographic
  * library Cyclone. None of this code has been edited;
  * the only change from the original code is the renaming of 
  * functions that we extracted. You can see the original naming 
  * as well as the URL to the function implementation above each
  * function. We chose the Cyclone crypto library because of its
  * advantages, such as compactness and speed, eliminating 
  * the need for I/O conversion. In other words, we do not need to
  * perform any conversion, such as pack/unpack or 
  * from_bytes/to_bytes, as required by other libraries like 
  * TweetNaCl or MonoCypher. Results from our speed measurements
  * have shown that Cyclone is approximately 5 times faster than
  * TweetNaCl (packing/unpacking not included).
  * Additionally, while MonoCypher is slightly faster (about 1.5x)
  * than Cyclone, there are highly efficient implementations written
  * in assembly language that outperform any C implementations. These
  * are particularly suitable for embedded  MCUs like the ARM 
  * Cortex-M4. Note that measurements were performed on a STM32 MCU
  * with a Cortex-M4 core.
  *
  * We also appreciate the maintenance of the Cyclone library, so we
  * are using the latest version, 2.3.0, released on June 12, 2023.
**/

/**
 * @file gf25519.h
 * @brief Curve25519 elliptic curve (constant-time implementation)
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2023 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneCRYPTO Open.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.3.0
 **/

#ifndef _GF25519_H
#define _GF25519_H

//Dependencies
#include "helpers.h"
//typedef unsigned int uint_t;   

/**
  * If __cplusplus is defined, meaning the code is being compiled
  * as C++, this line specifies that the following code should be
  * treated as C code rather than C++ code. This is important
  * because C and C++ have different name mangling rules
  * and linkage conventions.
  * https://en.cppreference.com/w/cpp/language/language_linkage
  * Do we want to use it?
**/
 
//C++ guard
// #ifdef __cplusplus
// extern "C" {
// #endif

//Curve25519 related functions

// Original name: curve25519Add
// URL: https://github.com/Oryx-Embedded/CycloneCRYPTO/blob/master/ecc/curve25519.c#L79C6-L79C19
void gf25519Add(u32 *r, const u32 *a, const u32 *b);

// Original name: curve25519Sub
// URL: https://github.com/Oryx-Embedded/CycloneCRYPTO/blob/master/ecc/curve25519.c#L130
void gf25519Sub(u32 *r, const u32 *a, const u32 *b);
  
// Original name: curve25519Mul
// URL: https://github.com/Oryx-Embedded/CycloneCRYPTO/blob/master/ecc/curve25519.c#L191 
void gf25519Mul(u32 *r, const u32 *a, const u32 *b);
 
// Original name: curve25519Red
// URL: https://github.com/Oryx-Embedded/CycloneCRYPTO/blob/master/ecc/curve25519.c#L352
void gf25519Red(u32 *r, const u32 *a);

// Original name: curve25519Sqr
// URL: https://github.com/Oryx-Embedded/CycloneCRYPTO/blob/master/ecc/curve25519.c#L317C18-L317C31
void gf25519Sqr(u32 *r, const u32 *a);

// Original name: curve25519Copy
// URL: https://github.com/Oryx-Embedded/CycloneCRYPTO/blob/master/ecc/curve25519.c#L515
void gf25519Copy(u32 *a, const u32 *b);

// Original name: curve25519Swap
// URL: https://github.com/Oryx-Embedded/CycloneCRYPTO/blob/master/ecc/curve25519.c#L534
void gf25519Swap(u32 *a, u32 *b, u32 c);

// Note: we replaced curve25519Select with gf25519Swap, so we dont need it anymore
// but feel free to use it, MACRO USE_GF25519SELECT
// Original name: curve25519Select
// URL: https://github.com/Oryx-Embedded/CycloneCRYPTO/blob/master/ecc/curve25519.c#L562
#ifdef USE_GF25519SELECT
void gf25519Select(u32 *r, const u32 *a, const u32 *b, u32 c);
#endif

// Original name: curve25519Comp
// URL: https://github.com/Oryx-Embedded/CycloneCRYPTO/blob/master/ecc/curve25519.c#L587
u32 gf25519Comp(const u32 *a, const u32 *b);

// Original name: curve25519Pwr2
// URL: https://github.com/Oryx-Embedded/CycloneCRYPTO/blob/master/ecc/curve25519.c#L331
void gf25519Pwr2(u32 *r, const u32 *a, size_t n);

//C++ guard
//#ifdef __cplusplus
//}
//#endif

#endif
