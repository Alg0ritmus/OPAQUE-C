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
 *  whichSha: [not a param, bcs. we will always be using sha512]
 *       SHA512
 * 
 *  Parameters:
 *      context: [in/out]
 *          The context to reset.
 *
 *  Returns:
 *      sha Error Code.
 *
 */

//STACKSIZE: 4B
uint32_t USHAReset(USHAContext *context)
{
  if (!context) return shaNull;
  context->whichSha = SHA512;
  return SHA512Reset((SHA512Context*)&context->ctx);
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

  return SHA512Input((SHA512Context*)&context->ctx, bytes,
      bytecount);

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
  return SHA512FinalBits((SHA512Context*)&context->ctx, bits,
          bit_count);

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
  return SHA512Result((SHA512Context*)&context->ctx,
                          Message_Digest);

  
}


/*
 * USHABlockSize
 * block size of SHA512
 *
 */
const uint32_t USHABlockSize = SHA512_Message_Block_Size;


/*
 * USHAHashSize

 * hash size of SHA512
 *
 */
const uint32_t USHAHashSize = SHA512HashSize;


/*
 * USHAHashSizeBits
 *   hash size in bits of SHA512
 *
 */
const uint32_t USHAHashSizeBits =  SHA512HashSizeBits;


/*
 * USHAHashName
 *   character string with the name in it
 *
 */
const char *USHAHashName = "SHA512";