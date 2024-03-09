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

// P.Z. A lot of function was removed or adjusted to use just whats
// needed. Also I added stack-size in desc. of every function.

/**************************** hkdf.c ***************************/
/***************** See RFC 6234 for details. *******************/
/* Copyright (c) 2011 IETF Trust and the persons identified as */
/* authors of the code.  All rights reserved.                  */
/* See sha.h for terms of use and redistribution.              */

/*
 *  Description:
 *      This file implements the HKDF algorithm (HMAC-based
 *      Extract-and-Expand Key Derivation Function, RFC 5869),
 *      expressed in terms of the various SHA algorithms.
 */

#include "sha.h"
#include <string.h>
#include <stdlib.h>

/*
 *  hkdf
 *
 *  Description:
 *      This function will generate keying material using HKDF.
 *
 *  whichSha: [not a param, bcs. we will always be using sha512]
 *          SHA512
 * 
 *  Parameters:
 *      salt[ ]: [in]
 *          The optional salt value (a non-secret random value);
 *          if not provided (salt == NULL), it is set internally
 *          to a string of HashLen(whichSha) zeros.
 *      salt_len: [in]
 *          The length of the salt value.  (Ignored if salt == NULL.)
 *      ikm[ ]: [in]
 *          Input keying material.
 *      ikm_len: [in]
 *          The length of the input keying material.
 *      info[ ]: [in]
 *          The optional context and application specific information.
 *          If info == NULL or a zero-length string, it is ignored.
 *      info_len: [in]
 *          The length of the optional context and application specific
 *          information.  (Ignored if info == NULL.)
 *      okm[ ]: [out]
 *          Where the HKDF is to be stored.
 *      okm_len: [in]
 *          The length of the buffer to hold okm.
 *          okm_len must be <= 255 * USHABlockSize(whichSha)
 *
 *  Notes:
 *      Calls hkdfExtract() and hkdfExpand().
 *
 *  Returns:
 *      sha Error Code.
 *
 */
//STACKSIZE: 64B + 1206B
uint32_t hkdf(
    const uint8_t *salt, uint32_t salt_len,
    const uint8_t *ikm, uint32_t ikm_len,
    const uint8_t *info, uint32_t info_len,
    uint8_t okm[ ], uint32_t okm_len)
{
  uint8_t prk[USHAMaxHashSize];
  return hkdfExtract(salt, salt_len, ikm, ikm_len, prk) ||
         hkdfExpand(prk, USHAHashSize, info,
                    info_len, okm, okm_len);
}

/*
 *  hkdfExtract
 *
 *  Description:
 *      This function will perform HKDF extraction.
 *
 *  whichSha: [not a param, bcs. we will always be using sha512]
 *          SHA512
 * 
 *  Parameters:
 *      salt[ ]: [in]
 *          The optional salt value (a non-secret random value);
 *          if not provided (salt == NULL), it is set internally
 *          to a string of HashLen(whichSha) zeros.
 *      salt_len: [in]
 *          The length of the salt value.  (Ignored if salt == NULL.)
 *      ikm[ ]: [in]
 *          Input keying material.
 *      ikm_len: [in]
 *          The length of the input keying material.
 *      prk[ ]: [out]
 *          Array where the HKDF extraction is to be stored.
 *          Must be larger than USHAHashSize(whichSha);
 *
 *  Returns:
 *      sha Error Code.
 *
 */
//STACKSIZE: 1206B
uint32_t hkdfExtract(
    const uint8_t *salt, int32_t salt_len,
    const uint8_t *ikm, uint32_t ikm_len,
    uint8_t prk[USHAMaxHashSize])
{
  uint8_t nullSalt[USHAMaxHashSize];
  if (salt == 0) {
    salt = nullSalt;
    salt_len = USHAHashSize;
    memset(nullSalt, '\0', salt_len);
  } else if (salt_len < 0) {
    return shaBadParam;
  }
  return hmac(ikm, ikm_len, salt, salt_len, prk);
}

/*
 *  hkdfExpand
 *
 *  Description:
 *      This function will perform HKDF expansion.
 *
 *  whichSha: [not a param, bcs. we will always be using sha512]
 *          SHA512
 *  Parameters:
 *      prk[ ]: [in]
 *          The pseudo-random key to be expanded; either obtained
 *          directly from a cryptographically strong, uniformly
 *          distributed pseudo-random number generator, or as the
 *          output from hkdfExtract().
 *      prk_len: [in]
 *          The length of the pseudo-random key in prk;
 *          should at least be equal to USHAHashSize(whichSHA).
 *      info[ ]: [in]
 *          The optional context and application specific information.
 *          If info == NULL or a zero-length string, it is ignored.
 *      info_len: [in]
 *          The length of the optional context and application specific
 *          information.  (Ignored if info == NULL.)
 *      okm[ ]: [out]
 *          Where the HKDF is to be stored.
 *      okm_len: [in]
 *          The length of the buffer to hold okm.
 *          okm_len must be <= 255 * USHABlockSize(whichSha)
 *
 *  Returns:
 *      sha Error Code.
 *
 */

// STACKSIZE: ~1034B
uint32_t hkdfExpand(
    const uint8_t prk[ ], uint32_t prk_len,
    const uint8_t *info, int32_t info_len,
    uint8_t okm[ ], uint32_t okm_len)
{
  uint32_t hash_len, N;
  uint8_t T[USHAMaxHashSize];
  uint32_t Tlen, where, i;

  if (info == 0) {
    info = (const uint8_t *)"";
    info_len = 0;
  } else if (info_len < 0) {
    return shaBadParam;
  }
  if (okm_len <= 0) return shaBadParam;
  if (!okm) return shaBadParam;

  hash_len = USHAHashSize;
  if (prk_len < hash_len) return shaBadParam;
  N = okm_len / hash_len;
  if ((okm_len % hash_len) != 0) N++;
  if (N > 255) return shaBadParam;

  Tlen = 0;
  where = 0;
  for (i = 1; i <= N; i++) {
    HMACContext context;
    uint8_t c = i;
    uint32_t ret = hmacReset(&context, prk, prk_len) ||
              hmacInput(&context, T, Tlen) ||
              hmacInput(&context, info, info_len) ||
              hmacInput(&context, &c, 1) ||
              hmacResult(&context, T);
    if (ret != shaSuccess) return ret;
    memcpy(okm + where, T,
           (i != N) ? hash_len : (okm_len - where));
    where += hash_len;
    Tlen = hash_len;
  }
  return shaSuccess;
}