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
  * This file contains all constants used in our ristretto255
  * implementation. All of the constants are taken from official
  * taken from ristretto draft:
  * https://datatracker.ietf.org/doc/draft-hdevalence-cfrg-ristretto/
  * and converted in suitable for our internal 8-word field_elem
  * representation of GF(2^255-19) element. To get more information
  * on field_elem repr. please check `helpers.h`
**/

#ifndef _RISTRETTO255_CONSTANTS_H
#define _RISTRETTO255_CONSTANTS_H

// Dependencies
#include "helpers.h"

// CONSTANTS taken from ristretto draft: https://datatracker.ietf.org/doc/draft-hdevalence-cfrg-ristretto/
static const field_elem F_ZERO = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000},
    F_ONE = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000},
    F_MODULUS = {0xFFFFFFED, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x7FFFFFFF},
    SQRT_M1 = {0x4A0EA0B0,0xC4EE1B27, 0xAD2FE478, 0x2F431806, 0x3DFBD7A7, 0x2B4D0099, 0x4FC1DF0B, 0x2B832480},
    EDWARDS_D = {0x135978A3, 0x75EB4DCA, 0x4141D8AB, 0x00700A4D, 0x7779E898, 0x8CC74079, 0x2B6FFE73, 0x52036CEE},
    EDWARDS_D2 = {0x26B2F159, 0xEBD69B94, 0x8283B156, 0x00E0149A, 0xEEF3D130, 0x198E80F2, 0x56DFFCE7, 0x2406D9DC},
    INVSQRT_A_MINUS_D  = {0x805D40EA, 0x99C8FDAA, 0x5A4172BE, 0x9D2F1617, 0xFE01D840, 0x16C27B91, 0xCFAFFCA2, 0x786C8905},
    ONE_MINUS_D_SQ = {0x945FC176, 0xE27C09C1, 0xCD5E350F, 0x2C81A138, 0xBE70DFE4, 0x9994ABDD, 0xB2B3E0D7, 0x029072A8},
    D_MINUS_ONE_SQ = {0x44ED4D20, 0x31AD5AAA, 0xB01E1999, 0xD29E4A2C, 0x529B4EEB, 0x4CDCD32F, 0xF66C2241, 0x5968B37A},
    SQRT_AD_MINUS_ONE = {0x497B2E1B, 0x7E97F6A0, 0x1B7854BD, 0xAF9D8E0C, 0x31F5D1FD, 0x0F3CFCC9, 0x2B8348AC, 0x376931BF};

#endif