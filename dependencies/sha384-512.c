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

// P.Z. A SHA384_512ProcessMessageBlock function was modified to
// use uint64_t W[16] array instead of W[80].




/************************* sha384-512.c ************************/
/***************** See RFC 6234 for details. *******************/
/* Copyright (c) 2011 IETF Trust and the persons identified as */
/* authors of the code.  All rights reserved.                  */
/* See sha.h for terms of use and redistribution.              */




/*
 * Description:
 *   This file implements the Secure Hash Algorithms SHA-384 and
 *   SHA-512 as defined in the U.S. National Institute of Standards
 *   and Technology Federal Information Processing Standards
 *   Publication (FIPS PUB) 180-3 published in October 2008
 *   and formerly defined in its predecessors, FIPS PUB 180-1
 *   and FIP PUB 180-2.
 *
 *   A combined document showing all algorithms is available at
 *       http://csrc.nist.gov/publications/fips/
 *              fips180-3/fips180-3_final.pdf
 *
 *   The SHA-384 and SHA-512 algorithms produce 384-bit and 512-bit
 *   message digests for a given data stream.  It should take about
 *   2**n steps to find a message with the same digest as a given
 *   message and 2**(n/2) to find any two messages with the same
 *   digest, when n is the digest size in bits.  Therefore, this
 *   algorithm can serve as a means of providing a
 *   "fingerprint" for a message.
 *
 * Portability Issues:
 *   SHA-384 and SHA-512 are defined in terms of 64-bit "words",
 *   but if USE_32BIT_ONLY is #defined, this code is implemented in
 *   terms of 32-bit "words".  This code uses <stdint.h> (included
 *   via "sha.h") to define the 64-, 32- and 8-bit unsigned integer
 *   types.  If your C compiler does not support 64-bit unsigned
 *   integers and you do not #define USE_32BIT_ONLY, this code is
 *   not appropriate.
 *
 * Caveats:
 *   SHA-384 and SHA-512 are designed to work with messages less
 *   than 2^128 bits long.  This implementation uses SHA384/512Input()
 *   to hash the bits that are a multiple of the size of an 8-bit
 *   octet, and then optionally uses SHA384/256FinalBits()
 *   to hash the final few bits of the input.
 *
 */

#include "sha.h"
#include "sha-private.h"

/* Define the SHA shift, rotate left and rotate right macros */
#define SHA512_SHR(bits,word)  (((uint64_t)(word)) >> (bits))
#define SHA512_ROTR(bits,word) ((((uint64_t)(word)) >> (bits)) | \
                                (((uint64_t)(word)) << (64-(bits))))

/*
 * Define the SHA SIGMA and sigma macros
 *
 *  SHA512_ROTR(28,word) ^ SHA512_ROTR(34,word) ^ SHA512_ROTR(39,word)
 */
#define SHA512_SIGMA0(word)   \
 (SHA512_ROTR(28,word) ^ SHA512_ROTR(34,word) ^ SHA512_ROTR(39,word))
#define SHA512_SIGMA1(word)   \
 (SHA512_ROTR(14,word) ^ SHA512_ROTR(18,word) ^ SHA512_ROTR(41,word))
#define SHA512_sigma0(word)   \
 (SHA512_ROTR( 1,word) ^ SHA512_ROTR( 8,word) ^ SHA512_SHR( 7,word))
#define SHA512_sigma1(word)   \
 (SHA512_ROTR(19,word) ^ SHA512_ROTR(61,word) ^ SHA512_SHR( 6,word))

/*
 * Add "length" to the length.
 * Set Corrupted when overflow has occurred.
 */
static uint64_t addTemp;
#define SHA384_512AddLength(context, length)                   \
   (addTemp = context->Length_Low, context->Corrupted =        \
    ((context->Length_Low += length) < addTemp) &&             \
    (++context->Length_High == 0) ? shaInputTooLong :          \
                                    (context)->Corrupted)

/* Local Function Prototypes */
static uint32_t SHA384_512Reset(SHA512Context *context,
                           uint64_t H0[SHA512HashSize/8]);
static void SHA384_512ProcessMessageBlock(SHA512Context *context);
static void SHA384_512Finalize(SHA512Context *context,
  uint8_t Pad_Byte);
static void SHA384_512PadMessage(SHA512Context *context,
  uint8_t Pad_Byte);
static uint32_t SHA384_512ResultN(SHA512Context *context,
  uint8_t Message_Digest[ ], uint32_t HashSize);

/* Initial Hash Values: FIPS 180-3 sections 5.3.4 and 5.3.5 */

static uint64_t SHA512_H0[ ] = {
    0x6A09E667F3BCC908ll, 0xBB67AE8584CAA73Bll, 0x3C6EF372FE94F82Bll,
    0xA54FF53A5F1D36F1ll, 0x510E527FADE682D1ll, 0x9B05688C2B3E6C1Fll,
    0x1F83D9ABFB41BD6Bll, 0x5BE0CD19137E2179ll
};


/*
 * SHA512Reset
 *
 * Description:
 *   This function will initialize the SHA512Context in preparation
 *   for computing a new SHA512 message digest.
 *
 * Parameters:
 *   context: [in/out]
 *     The context to reset.
 *
 * Returns:
 *   sha Error Code.
 *
 */
uint32_t SHA512Reset(SHA512Context *context)
{
  return SHA384_512Reset(context, SHA512_H0);
}

/*
 * SHA512Input
 *
 * Description:
 *   This function accepts an array of octets as the next portion
 *   of the message.
 *
 * Parameters:
 *   context: [in/out]
 *     The SHA context to update.
 *   message_array[ ]: [in]
 *     An array of octets representing the next portion of
 *     the message.
 *   length: [in]
 *     The length of the message in message_array.
 *
 * Returns:
 *   sha Error Code.
 *
 */
uint32_t SHA512Input(SHA512Context *context,
        const uint8_t *message_array,
        uint32_t length)
{
  if (!context) return shaNull;
  if (!length) return shaSuccess;
  if (!message_array) return shaNull;
  if (context->Computed) return context->Corrupted = shaStateError;
  if (context->Corrupted) return context->Corrupted;

  while (length--) {
    context->Message_Block[context->Message_Block_Index++] =
            *message_array;

    if ((SHA384_512AddLength(context, 8) == shaSuccess) &&
      (context->Message_Block_Index == SHA512_Message_Block_Size))
      SHA384_512ProcessMessageBlock(context);

    message_array++;
  }

  return context->Corrupted;
}

/*
 * SHA512FinalBits
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
 *
 */
uint32_t SHA512FinalBits(SHA512Context *context,
                    uint8_t message_bits, uint32_t length)
{
  static uint8_t masks[8] = {
      /* 0 0b00000000 */ 0x00, /* 1 0b10000000 */ 0x80,
      /* 2 0b11000000 */ 0xC0, /* 3 0b11100000 */ 0xE0,
      /* 4 0b11110000 */ 0xF0, /* 5 0b11111000 */ 0xF8,
      /* 6 0b11111100 */ 0xFC, /* 7 0b11111110 */ 0xFE
  };
  static uint8_t markbit[8] = {
      /* 0 0b10000000 */ 0x80, /* 1 0b01000000 */ 0x40,
      /* 2 0b00100000 */ 0x20, /* 3 0b00010000 */ 0x10,
      /* 4 0b00001000 */ 0x08, /* 5 0b00000100 */ 0x04,
      /* 6 0b00000010 */ 0x02, /* 7 0b00000001 */ 0x01
  };

  if (!context) return shaNull;
  if (!length) return shaSuccess;
  if (context->Corrupted) return context->Corrupted;
  if (context->Computed) return context->Corrupted = shaStateError;
  if (length >= 8) return context->Corrupted = shaBadParam;

  SHA384_512AddLength(context, length);
  SHA384_512Finalize(context, (uint8_t)
    ((message_bits & masks[length]) | markbit[length]));

  return context->Corrupted;
}

/*
 * SHA512Result
 *
 * Description:
 *   This function will return the 512-bit message digest
 *   into the Message_Digest array provided by the caller.
 *   NOTE:
 *    The first octet of hash is stored in the element with index 0,
 *    the last octet of hash in the element with index 63.
 *
 * Parameters:
 *   context: [in/out]
 *     The context to use to calculate the SHA hash.
 *   Message_Digest[ ]: [out]
 *     Where the digest is returned.
 *
 * Returns:
 *   sha Error Code.
 *
 */
uint32_t SHA512Result(SHA512Context *context,
    uint8_t Message_Digest[SHA512HashSize])
{
  return SHA384_512ResultN(context, Message_Digest, SHA512HashSize);
}

/*
 * SHA384_512Reset
 *
 * Description:
 *   This helper function will initialize the SHA512Context in
 *   preparation for computing a new SHA384 or SHA512 message
 *   digest.
 *
 * Parameters:
 *   context: [in/out]
 *     The context to reset.
 *   H0[ ]: [in]
 *     The initial hash value array to use.
 *
 * Returns:
 *   sha Error Code.
 *
 */

static uint32_t SHA384_512Reset(SHA512Context *context,
                           uint64_t H0[SHA512HashSize/8])

{
  uint32_t i;
  if (!context) return shaNull;
  context->Message_Block_Index = 0;


  context->Length_High = context->Length_Low = 0;

  for (i = 0; i < SHA512HashSize/8; i++)
    context->Intermediate_Hash[i] = H0[i];


  context->Computed = 0;
  context->Corrupted = shaSuccess;

  return shaSuccess;
}

/*
 * SHA384_512ProcessMessageBlock
 *
 * Description:
 *   This helper function will process the next 1024 bits of the
 *   message stored in the Message_Block array.
 *
 * Parameters:
 *   context: [in/out]
 *     The SHA context to update.
 *
 * Returns:
 *   Nothing.
 *
 * Comments:
 *   Many of the variable names in this code, especially the
 *   single character names, were used because those were the
 *   names used in the Secure Hash Standard.
 *
 *
 */
static void SHA384_512ProcessMessageBlock(SHA512Context *context)
{

  static const uint64_t K[80] = {
      0x428A2F98D728AE22ll, 0x7137449123EF65CDll, 0xB5C0FBCFEC4D3B2Fll,
      0xE9B5DBA58189DBBCll, 0x3956C25BF348B538ll, 0x59F111F1B605D019ll,
      0x923F82A4AF194F9Bll, 0xAB1C5ED5DA6D8118ll, 0xD807AA98A3030242ll,
      0x12835B0145706FBEll, 0x243185BE4EE4B28Cll, 0x550C7DC3D5FFB4E2ll,
      0x72BE5D74F27B896Fll, 0x80DEB1FE3B1696B1ll, 0x9BDC06A725C71235ll,
      0xC19BF174CF692694ll, 0xE49B69C19EF14AD2ll, 0xEFBE4786384F25E3ll,
      0x0FC19DC68B8CD5B5ll, 0x240CA1CC77AC9C65ll, 0x2DE92C6F592B0275ll,
      0x4A7484AA6EA6E483ll, 0x5CB0A9DCBD41FBD4ll, 0x76F988DA831153B5ll,
      0x983E5152EE66DFABll, 0xA831C66D2DB43210ll, 0xB00327C898FB213Fll,
      0xBF597FC7BEEF0EE4ll, 0xC6E00BF33DA88FC2ll, 0xD5A79147930AA725ll,
      0x06CA6351E003826Fll, 0x142929670A0E6E70ll, 0x27B70A8546D22FFCll,
      0x2E1B21385C26C926ll, 0x4D2C6DFC5AC42AEDll, 0x53380D139D95B3DFll,
      0x650A73548BAF63DEll, 0x766A0ABB3C77B2A8ll, 0x81C2C92E47EDAEE6ll,
      0x92722C851482353Bll, 0xA2BFE8A14CF10364ll, 0xA81A664BBC423001ll,
      0xC24B8B70D0F89791ll, 0xC76C51A30654BE30ll, 0xD192E819D6EF5218ll,
      0xD69906245565A910ll, 0xF40E35855771202All, 0x106AA07032BBD1B8ll,
      0x19A4C116B8D2D0C8ll, 0x1E376C085141AB53ll, 0x2748774CDF8EEB99ll,
      0x34B0BCB5E19B48A8ll, 0x391C0CB3C5C95A63ll, 0x4ED8AA4AE3418ACBll,
      0x5B9CCA4F7763E373ll, 0x682E6FF3D6B2B8A3ll, 0x748F82EE5DEFB2FCll,
      0x78A5636F43172F60ll, 0x84C87814A1F0AB72ll, 0x8CC702081A6439ECll,
      0x90BEFFFA23631E28ll, 0xA4506CEBDE82BDE9ll, 0xBEF9A3F7B2C67915ll,
      0xC67178F2E372532Bll, 0xCA273ECEEA26619Cll, 0xD186B8C721C0C207ll,
      0xEADA7DD6CDE0EB1Ell, 0xF57D4F7FEE6ED178ll, 0x06F067AA72176FBAll,
      0x0A637DC5A2C898A6ll, 0x113F9804BEF90DAEll, 0x1B710B35131C471Bll,
      0x28DB77F523047D84ll, 0x32CAAB7B40C72493ll, 0x3C9EBE0A15C9BEBCll,
      0x431D67C49C100D4Cll, 0x4CC5D4BECB3E42B6ll, 0x597F299CFC657E2All,
      0x5FCB6FAB3AD6FAECll, 0x6C44198C4A475817ll
  };
  uint32_t        t, t8;                   /* Loop counter */
  uint64_t   temp1, temp2, s0, s1;            /* Temporary word value */
  uint64_t   W[16];                   /* Word sequence */
  uint64_t   A, B, C, D, E, F, G, H;  /* Word buffers */

  /*
   * Initialize the first 16 words in the array W
   */

  A = context->Intermediate_Hash[0];
  B = context->Intermediate_Hash[1];
  C = context->Intermediate_Hash[2];
  D = context->Intermediate_Hash[3];
  E = context->Intermediate_Hash[4];
  F = context->Intermediate_Hash[5];
  G = context->Intermediate_Hash[6];
  H = context->Intermediate_Hash[7];

  for (t = t8 = 0; t < 16; t++, t8 += 8){
    W[t] = ((uint64_t)(context->Message_Block[t8  ]) << 56) |
           ((uint64_t)(context->Message_Block[t8 + 1]) << 48) |
           ((uint64_t)(context->Message_Block[t8 + 2]) << 40) |
           ((uint64_t)(context->Message_Block[t8 + 3]) << 32) |
           ((uint64_t)(context->Message_Block[t8 + 4]) << 24) |
           ((uint64_t)(context->Message_Block[t8 + 5]) << 16) |
           ((uint64_t)(context->Message_Block[t8 + 6]) << 8) |
           ((uint64_t)(context->Message_Block[t8 + 7]));

    temp1 = H;
    temp1 += SHA512_SIGMA1(E);
    temp1 += SHA_Ch(E, F, G);
    temp1 += K[t];
    temp1 += W[t];

    temp2 = SHA512_SIGMA0(A);
    temp2 += SHA_Maj(A, B, C);

    H = G;
    G = F;
    F = E;
    E = D + temp1;
    D = C;
    C = B;
    B = A;
    A = temp1 + temp2;
  }


  for (t = 16; t < 80; t++){

    s0 = W[(t + 1) & 0x0f];
    s0 = SHA512_sigma0(s0);
    s1 = W[(t + 14) & 0x0f];
    s1 = SHA512_sigma1(s1);

    temp1 = W[t & 0xf] += s0 + s1 + W[(t + 9) & 0xf];
    temp1 += H + SHA512_SIGMA1(E) + SHA_Ch(E, F, G) + K[t];
    temp2 = SHA512_SIGMA0(A) + SHA_Maj(A, B, C);

    H = G;
    G = F;
    F = E;
    E = D + temp1;
    D = C;
    C = B;
    B = A;
    A = temp1 + temp2;
  }

  context->Intermediate_Hash[0] += A;
  context->Intermediate_Hash[1] += B;
  context->Intermediate_Hash[2] += C;
  context->Intermediate_Hash[3] += D;
  context->Intermediate_Hash[4] += E;
  context->Intermediate_Hash[5] += F;
  context->Intermediate_Hash[6] += G;
  context->Intermediate_Hash[7] += H;

  context->Message_Block_Index = 0;
}

/*
 * SHA384_512Finalize
 *
 * Description:
 *   This helper function finishes off the digest calculations.
 *
 * Parameters:
 *   context: [in/out]
 *     The SHA context to update.
 *   Pad_Byte: [in]
 *     The last byte to add to the message block before the 0-padding
 *     and length.  This will contain the last bits of the message
 *     followed by another single bit.  If the message was an
 *     exact multiple of 8-bits long, Pad_Byte will be 0x80.
 *
 * Returns:
 *   sha Error Code.
 *
 */
static void SHA384_512Finalize(SHA512Context *context,
    uint8_t Pad_Byte)
{
  int_least16_t i;
  SHA384_512PadMessage(context, Pad_Byte);
  /* message may be sensitive, clear it out */
  for (i = 0; i < SHA512_Message_Block_Size; ++i)
    context->Message_Block[i] = 0;

  context->Length_High = context->Length_Low = 0;

  context->Computed = 1;
}

/*
 * SHA384_512PadMessage
 *
 * Description:
 *   According to the standard, the message must be padded to the next
 *   even multiple of 1024 bits.  The first padding bit must be a '1'.
 *   The last 128 bits represent the length of the original message.
 *   All bits in between should be 0.  This helper function will
 *   pad the message according to those rules by filling the
 *   Message_Block array accordingly.  When it returns, it can be
 *   assumed that the message digest has been computed.
 *
 * Parameters:
 *   context: [in/out]
 *     The context to pad.
 *   Pad_Byte: [in]
 *     The last byte to add to the message block before the 0-padding
 *     and length.  This will contain the last bits of the message
 *     followed by another single bit.  If the message was an
 *     exact multiple of 8-bits long, Pad_Byte will be 0x80.
 *
 * Returns:
 *   Nothing.
 *
 */
static void SHA384_512PadMessage(SHA512Context *context,
    uint8_t Pad_Byte)
{
  /*
   * Check to see if the current message block is too small to hold
   * the initial padding bits and length.  If so, we will pad the
   * block, process it, and then continue padding into a second
   * block.
   */
  if (context->Message_Block_Index >= (SHA512_Message_Block_Size-16)) {
    context->Message_Block[context->Message_Block_Index++] = Pad_Byte;
    while (context->Message_Block_Index < SHA512_Message_Block_Size)
      context->Message_Block[context->Message_Block_Index++] = 0;

    SHA384_512ProcessMessageBlock(context);
  } else
    context->Message_Block[context->Message_Block_Index++] = Pad_Byte;

  while (context->Message_Block_Index < (SHA512_Message_Block_Size-16))
    context->Message_Block[context->Message_Block_Index++] = 0;

  /*
   * Store the message length as the last 16 octets
   */

  context->Message_Block[112] = (uint8_t)(context->Length_High >> 56);
  context->Message_Block[113] = (uint8_t)(context->Length_High >> 48);
  context->Message_Block[114] = (uint8_t)(context->Length_High >> 40);
  context->Message_Block[115] = (uint8_t)(context->Length_High >> 32);
  context->Message_Block[116] = (uint8_t)(context->Length_High >> 24);
  context->Message_Block[117] = (uint8_t)(context->Length_High >> 16);
  context->Message_Block[118] = (uint8_t)(context->Length_High >> 8);
  context->Message_Block[119] = (uint8_t)(context->Length_High);

  context->Message_Block[120] = (uint8_t)(context->Length_Low >> 56);
  context->Message_Block[121] = (uint8_t)(context->Length_Low >> 48);
  context->Message_Block[122] = (uint8_t)(context->Length_Low >> 40);
  context->Message_Block[123] = (uint8_t)(context->Length_Low >> 32);
  context->Message_Block[124] = (uint8_t)(context->Length_Low >> 24);
  context->Message_Block[125] = (uint8_t)(context->Length_Low >> 16);
  context->Message_Block[126] = (uint8_t)(context->Length_Low >> 8);
  context->Message_Block[127] = (uint8_t)(context->Length_Low);


  SHA384_512ProcessMessageBlock(context);
}

/*
 * SHA384_512ResultN
 *
 * Description:
 *   This helper function will return the 384-bit or 512-bit message
 *   digest into the Message_Digest array provided by the caller.
 *   NOTE:
 *    The first octet of hash is stored in the element with index 0,
 *    the last octet of hash in the element with index 47/63.
 *
 * Parameters:
 *   context: [in/out]
 *     The context to use to calculate the SHA hash.
 *   Message_Digest[ ]: [out]
 *     Where the digest is returned.
 *   HashSize: [in]
 *     The size of the hash, either 48 or 64.
 *
 * Returns:
 *   sha Error Code.
 *
 */
static uint32_t SHA384_512ResultN(SHA512Context *context,
    uint8_t Message_Digest[ ], uint32_t HashSize)
{
  uint32_t i;

  if (!context) return shaNull;
  if (!Message_Digest) return shaNull;
  if (context->Corrupted) return context->Corrupted;

  if (!context->Computed)
    SHA384_512Finalize(context, 0x80);

  for (i = 0; i < HashSize; ++i)
    Message_Digest[i] = (uint8_t)
      (context->Intermediate_Hash[i>>3] >> 8 * ( 7 - ( i % 8 ) ));

  return shaSuccess;
}

