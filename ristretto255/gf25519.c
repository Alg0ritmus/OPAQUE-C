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
  * @file gf25519.c
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
  
  
 //Dependencies
 #include "gf25519.h"
 

 /**
  * @brief Modular addition
  * @param[out] r Resulting integer R = (A + B) mod p
  * @param[in] a An integer such as 0 <= A < p
  * @param[in] b An integer such as 0 <= B < p
  **/
  
 // Original name: curve25519Add
 // URL: https://github.com/Oryx-Embedded/CycloneCRYPTO/blob/master/ecc/curve25519.c#L79C6-L79C19
 void gf25519Add(u32 *r, const u32 *a, const u32 *b)
 {
    size_t i;
    u64 temp;
  
    //Compute R = A + B
    for(temp = 0, i = 0; i < 8; i++)
    {
       temp += a[i];
       temp += b[i];
       r[i] = temp & 0xFFFFFFFF;
       temp >>= 32;
    }
  
    //Perform modular reduction
    gf25519Red(r, r);
 }
   
  
 /**
  * @brief Modular subtraction
  * @param[out] r Resulting integer R = (A - B) mod p
  * @param[in] a An integer such as 0 <= A < p
  * @param[in] b An integer such as 0 <= B < p
  **/
  
 // Original name: curve25519Sub
 // URL: https://github.com/Oryx-Embedded/CycloneCRYPTO/blob/master/ecc/curve25519.c#L130
 void gf25519Sub(u32 *r, const u32 *a, const u32 *b)
 {
    size_t i;
    int64_t temp;
  
    //Compute R = A - 19 - B
    for(temp = -19, i = 0; i < 8; i++)
    {
       temp += a[i];
       temp -= b[i];
       r[i] = temp & 0xFFFFFFFF;
       temp >>= 32;
    }
  
    //Compute R = A + (2^255 - 19) - B
    r[7] += 0x80000000;
  
    //Perform modular reduction
    gf25519Red(r, r);
 }
  
  
  
 /**
  * @brief Modular multiplication
  * @param[out] r Resulting integer R = (A * B) mod p
  * @param[in] a An integer such as 0 <= A < p
  * @param[in] b An integer such as 0 <= B < p
  **/
  
 // Original name: curve25519Mul
 // URL: https://github.com/Oryx-Embedded/CycloneCRYPTO/blob/master/ecc/curve25519.c#L191 
 void gf25519Mul(u32 *r, const u32 *a, const u32 *b)
 {
    size_t i;
    size_t j;
    u64 c;
    u64 temp;
    u32 u[16];
  
    //Initialize variables
    temp = 0;
    c = 0;
  
    //Comba's method is used to perform multiplication
    for(i = 0; i < 16; i++)
    {
       //The algorithm computes the products, column by column
       if(i < 8)
       {
          //Inner loop
          for(j = 0; j <= i; j++)
          {
             temp += (u64) a[j] * b[i - j];
             c += temp >> 32;
             temp &= 0xFFFFFFFF;
          }
       }
       else
       {
          //Inner loop
          for(j = i - 7; j < 8; j++)
          {
             temp += (u64) a[j] * b[i - j];
             c += temp >> 32;
             temp &= 0xFFFFFFFF;
          }
       }
  
       //At the bottom of each column, the final result is written to memory
       u[i] = temp & 0xFFFFFFFF;
  
       //Propagate the carry upwards
       temp = c & 0xFFFFFFFF;
       c >>= 32;
    }
  
    //Reduce bit 255 (2^255 = 19 mod p)
    temp = (u[7] >> 31) * 19;
    //Mask the most significant bit
    u[7] &= 0x7FFFFFFF;
  
    //Perform fast modular reduction (first pass)
    for(i = 0; i < 8; i++)
    {
       temp += u[i];
       temp += (u64) u[i + 8] * 38;
       u[i] = temp & 0xFFFFFFFF;
       temp >>= 32;
    }
  
    //Reduce bit 256 (2^256 = 38 mod p)
    temp *= 38;
    //Reduce bit 255 (2^255 = 19 mod p)
    temp += (u[7] >> 31) * 19;
    //Mask the most significant bit
    u[7] &= 0x7FFFFFFF;
  
    //Perform fast modular reduction (second pass)
    for(i = 0; i < 8; i++)
    {
       temp += u[i];
       u[i] = temp & 0xFFFFFFFF;
       temp >>= 32;
    }
  
    //Reduce non-canonical values
    gf25519Red(r, u);
 }

  
  
 /**
  * @brief Modular squaring
  * @param[out] r Resulting integer R = (A ^ 2) mod p
  * @param[in] a An integer such as 0 <= A < p
  **/
 
 // Original name: curve25519Sqr
 // URL: https://github.com/Oryx-Embedded/CycloneCRYPTO/blob/master/ecc/curve25519.c#L317C18-L317C31
 void gf25519Sqr(u32 *r, const u32 *a)
 {
    //Compute R = (A ^ 2) mod p
    gf25519Mul(r, a, a);
 }
  
  
 /**
  * @brief Raise an integer to power 2^n
  * @param[out] r Resulting integer R = (A ^ (2^n)) mod p
  * @param[in] a An integer such as 0 <= A < p
  * @param[in] n An integer such as n >= 1
  **/
 
 // Original name: curve25519Pwr2
 // URL: https://github.com/Oryx-Embedded/CycloneCRYPTO/blob/master/ecc/curve25519.c#L331
 void gf25519Pwr2(u32 *r, const u32 *a, size_t n)
 {
    size_t i;
  
    //Pre-compute (A ^ 2) mod p
    gf25519Sqr(r, a);
  
    //Compute R = (A ^ (2^n)) mod p
    for(i = 1; i < n; i++)
    {
       gf25519Sqr(r, r);
    }
 }
  
  
 /**
  * @brief Modular reduction
  * @param[out] r Resulting integer R = A mod p
  * @param[in] a An integer such as 0 <= A < (2 * p)
  **/
 
 // Original name: curve25519Red
 // URL: https://github.com/Oryx-Embedded/CycloneCRYPTO/blob/master/ecc/curve25519.c#L352
 void gf25519Red(u32 *r, const u32 *a)
 {
    size_t i;
    u64 temp;
    u32 b[8];
  
    //Compute B = A + 19
    for(temp = 19, i = 0; i < 8; i++)
    {
       temp += a[i];
       b[i] = temp & 0xFFFFFFFF;
       temp >>= 32;
    }
  
    //Compute B = A - (2^255 - 19)
    b[7] -= 0x80000000;
  
    //If B < (2^255 - 19) then R = B, else R = A
    #ifdef USE_GF25519SELECT
    gf25519Select(r, b, a, (b[7] & 0x80000000) >> 31);
    #else
    gf25519Copy(r,a);
    gf25519Swap(r,b, !((b[7] & 0x80000000) >> 31));
    #endif //USE_GF25519SELECT
 }
    
  
 /**
  * @brief Copy an integer
  * @param[out] a Pointer to the destination integer
  * @param[in] b Pointer to the source integer
  **/
 
 // Original name: curve25519Copy
 // URL: https://github.com/Oryx-Embedded/CycloneCRYPTO/blob/master/ecc/curve25519.c#L515
 void gf25519Copy(u32 *a, const u32 *b)
 {
    size_t i;
  
    //Copy the value of the integer
    for(i = 0; i < 8; i++)
    {
       a[i] = b[i];
    }
 }
  
  
 /**
  * @brief Conditional swap
  * @param[in,out] a Pointer to the first integer
  * @param[in,out] b Pointer to the second integer
  * @param[in] c Condition variable
  **/

 // Original name: curve25519Swap
 // URL: https://github.com/Oryx-Embedded/CycloneCRYPTO/blob/master/ecc/curve25519.c#L534
 void gf25519Swap(u32 *a, u32 *b, u32 c)
 {
    size_t i;
    u32 mask;
    u32 dummy;
  
    //The mask is the all-1 or all-0 word
    mask = ~c + 1; 
 
    //Conditional swap
    for(i = 0; i < 8; i++)
    {
       //Constant time implementation
       dummy = mask & (a[i] ^ b[i]);
       a[i] ^= dummy;
       b[i] ^= dummy;
    }
 }
  


  
 /**
  * @brief Select an integer
  * @param[out] r Pointer to the destination integer
  * @param[in] a Pointer to the first source integer
  * @param[in] b Pointer to the second source integer
  * @param[in] c Condition variable
  **/
  
 // Original name: curve25519Select
 // URL: https://github.com/Oryx-Embedded/CycloneCRYPTO/blob/master/ecc/curve25519.c#L562
 #ifdef USE_GF25519SELECT
 void gf25519Select(u32 *r, const u32 *a, const u32 *b,
    u32 c)
 {
    size_t i;
    u32 mask;
  
    //The mask is the all-1 or all-0 word
    mask = c - 1;
  
    //Select between A and B
    for(i = 0; i < 8; i++)
    {
       //Constant time implementation
       r[i] = (a[i] & mask) | (b[i] & ~mask);
    }
 }
 #endif //USE_GF25519SELECT 
  
 /**
  * @brief Compare integers
  * @param[in] a Pointer to the first integer
  * @param[in] b Pointer to the second integer
  * @return The function returns 0 if the A = B, else 1
  **/
 
 // Original name: curve25519Comp
 // URL: https://github.com/Oryx-Embedded/CycloneCRYPTO/blob/master/ecc/curve25519.c#L587
 u32 gf25519Comp(const u32 *a, const u32 *b)
 {
    size_t i;
    u32 mask;
  
    //Initialize mask
    mask = 0;
  
    //Compare A and B
    for(i = 0; i < 8; i++)
    {
       //Constant time implementation
       mask |= a[i] ^ b[i];
    }
  
    //Return 0 if A = B, else 1, NOTE: that we need reversed logic in ristretto.c for our needs
    return (((u32) (mask | (~mask + 1))) >> 31); 
 }

