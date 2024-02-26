// ******************************************************************
// ----------------- TECHNICAL UNIVERSITY OF KOSICE -----------------
// ---Department of Electronics and Multimedia Telecommunications ---
// -------- FACULTY OF ELECTRICAL ENGINEERING AND INFORMATICS -------
// ------------ THIS CODE IS A PART OF A MASTER'S THESIS ------------
// ------------------------- Master thesis --------------------------
// -----------------Patrik Zelenak & Milos Drutarovsky --------------
// ---------------------------version T.T.2 -------------------------
// --------------------------- 21-02-2023 ---------------------------
// ******************************************************************

// P.Z. A lot of function was removed or adjusted to use just whats
// needed.

/**************************** usha.c ***************************/
/***************** See RFC 6234 for details. *******************/
/* Copyright (c) 2011 IETF Trust and the persons identified as */
/* authors of the code.  All rights reserved.                  */
/* See sha.h for terms of use and redistribution.              */

/*
 *  Description:
 *     This file implements a unified interface to the SHA algorithms.
 */

#include "sha.h"

/*
 *  USHAReset
 *
 *  Description:
 *      This function will initialize the SHA Context in preparation
 *      for computing a new SHA message digest.
 *
 *  Parameters:
 *      context: [in/out]
 *          The context to reset.
 *      whichSha: [in]
 *          Selects which SHA reset to call
 *
 *  Returns:
 *      sha Error Code.
 *
 */

//STACKSIZE: 4B
uint32_t USHAReset(USHAContext *context, enum SHAversion whichSha)
{
  if (!context) return shaNull;
  context->whichSha = whichSha;
  switch (whichSha) {
    case SHA512: return SHA512Reset((SHA512Context*)&context->ctx);
    default: return shaBadParam;
  }
}

/*
 *  USHAInput
 *
 *  Description:
 *      This function accepts an array of octets as the next portion
 *      of the message.
 *
 *  Parameters:
 *      context: [in/out]
 *          The SHA context to update.
 *      message_array: [in]
 *          An array of octets representing the next portion of
 *          the message.
 *      length: [in]
 *          The length of the message in message_array.
 *
 *  Returns:
 *      sha Error Code.
 *
 */

// STACKSIZE: ~738B
uint32_t USHAInput(USHAContext *context,
              const uint8_t *bytes,uint32_t bytecount)
{
  if (!context) return shaNull;
  switch (context->whichSha) {
    case SHA512:
      return SHA512Input((SHA512Context*)&context->ctx, bytes,
          bytecount);
    default: return shaBadParam;
  }
}

/*
 * USHAFinalBits
 *
 * Description:
 *   This function will add in any final bits of the message.
 *
 * Parameters:
 *   context: [in/out]
 *     The SHA context to update.
 *   message_bits: [in]
 *     The final bits of the message, in the upper portion of the
 *     byte.  (Use 0b###00000 instead of 0b00000### to input the
 *     three bits ###.)
 *   length: [in]
 *     The number of bits in message_bits, between 1 and 7.
 *
 * Returns:
 *   sha Error Code.
 */

// STACKSIZE: ~764B
uint32_t USHAFinalBits(USHAContext *context,
                  uint8_t bits,uint32_t bit_count)
{
  if (!context) return shaNull;
  switch (context->whichSha) {
    case SHA512:
      return SHA512FinalBits((SHA512Context*)&context->ctx, bits,
          bit_count);
    default: return shaBadParam;
  }
}

/*
 * USHAResult
 *
 * Description:
 *   This function will return the message digest of the appropriate
 *   bit size, as returned by USHAHashSizeBits(whichSHA) for the
 *   'whichSHA' value used in the preceeding call to USHAReset,
 *   into the Message_Digest array provided by the caller.
 *
 * Parameters:
 *   context: [in/out]
 *     The context to use to calculate the SHA-1 hash.
 *   Message_Digest: [out]
 *     Where the digest is returned.
 *
 * Returns:
 *   sha Error Code.
 *
 */

//STACKSIZE: ~742B
uint32_t USHAResult(USHAContext *context,
               uint8_t Message_Digest[USHAMaxHashSize])
{
  if (!context) return shaNull;
  switch (context->whichSha) {
    case SHA512:
      return SHA512Result((SHA512Context*)&context->ctx,
                          Message_Digest);
    default: return shaBadParam;
  }
}

/*
 * USHABlockSize
 *
 * Description:
 *   This function will return the blocksize for the given SHA
 *   algorithm.
 *
 * Parameters:
 *   whichSha:
 *     which SHA algorithm to query
 *
 * Returns:
 *   block size
 *
 */
uint32_t USHABlockSize()
{
  return SHA512_Message_Block_Size;
}

/*
 * USHAHashSize
 *
 * Description:
 *   This function will return the hashsize for the given SHA
 *   algorithm.
 *
 * Parameters:
 *   whichSha:
 *     which SHA algorithm to query
 *
 * Returns:
 *   hash size
 *
 */
uint32_t USHAHashSize()
{
  return SHA512HashSize;
  
}

/*
 * USHAHashSizeBits
 *
 * Description:
 *   This function will return the hashsize for the given SHA
 *   algorithm, expressed in bits.
 *
 * Parameters:
 *   whichSha:
 *     which SHA algorithm to query
 *
 * Returns:
 *   hash size in bits
 *
 */
uint32_t USHAHashSizeBits()
{
  
  return SHA512HashSizeBits;

}

/*
 * USHAHashName
 *
 * Description:
 *   This function will return the name of the given SHA algorithm
 *   as a string.
 *
 * Parameters:
 *   whichSha:
 *     which SHA algorithm to query
 *
 * Returns:
 *   character string with the name in it
 *
 */
const char *USHAHashName()
{
  
  return "SHA512";
}

