// ******************************************************************
// ----------------- TECHNICAL UNIVERSITY OF KOSICE -----------------
// ---Department of Electronics and Multimedia Telecommunications ---
// -------- FACULTY OF ELECTRICAL ENGINEERING AND INFORMATICS -------
// ------------ THIS CODE IS A PART OF A MASTER'S THESIS ------------
// ------------------------- Master thesis --------------------------
// -----------------Patrik Zelenak & Milos Drutarovsky --------------
// ---------------------------version 1.1.0 -------------------------
// --------------------------- 20-03-2024 ---------------------------
// ******************************************************************

// P.Z. A lot of function was removed or adjusted to use just whats
// needed.

/**************************** sha.h ****************************/
/***************** See RFC 6234 for details. *******************/
/*
   Copyright (c) 2011 IETF Trust and the persons identified as
   authors of the code.  All rights reserved.

   Redistribution and use in source and binary forms, with or
   without modification, are permitted provided that the following
   conditions are met:

   - Redistributions of source code must retain the above
     copyright notice, this list of conditions and
     the following disclaimer.

   - Redistributions in binary form must reproduce the above
     copyright notice, this list of conditions and the following
     disclaimer in the documentation and/or other materials provided
     with the distribution.

   - Neither the name of Internet Society, IETF or IETF Trust, nor
     the names of specific contributors, may be used to endorse or
     promote products derived from this software without specific
     prior written permission.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
   CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
   INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
   MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
   DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
   CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
   NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
   LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
   CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
   OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
   EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#ifndef _SHA_H_
#define _SHA_H_

/*
 *  Description:
 *      This file implements the Secure Hash Algorithms
 *      as defined in the U.S. National Institute of Standards
 *      and Technology Federal Information Processing Standards
 *      Publication (FIPS PUB) 180-3 published in October 2008
 *      and formerly defined in its predecessors, FIPS PUB 180-1
 *      and FIP PUB 180-2.
 *
 *      A combined document showing all algorithms is available at
 *              http://csrc.nist.gov/publications/fips/
 *                     fips180-3/fips180-3_final.pdf
 *
 *      The five hashes are defined in these sizes:
 *              SHA-1           20 byte / 160 bit
 *              SHA-224         28 byte / 224 bit
 *              SHA-256         32 byte / 256 bit
 *              SHA-384         48 byte / 384 bit
 *              SHA-512         64 byte / 512 bit
 *
 *  Compilation Note:
 *    These files may be compiled with two options:
 *        USE_32BIT_ONLY - use 32-bit arithmetic only, for systems
 *                         without 64-bit integers
 *
 *        USE_MODIFIED_MACROS - use alternate form of the SHA_Ch()
 *                         and SHA_Maj() macros that are equivalent
 *                         and potentially faster on many systems
 *
 */

#include <stdint.h>
/*
 * If you do not have the ISO standard stdint.h header file, then you
 * must typedef the following:
 *    name              meaning
 *  uint64_t         unsigned 64-bit integer
 *  uint32_t         unsigned 32-bit integer
 *  uint8_t          unsigned 8-bit integer (i.e., uint8_t)
 *  int_least16_t    integer of >= 16 bits
 *
 * See stdint-example.h
 */

#ifndef _SHA_enum_
#define _SHA_enum_
/*
 *  All SHA functions return one of these values.
 */
enum {
    shaSuccess = 0,
    shaNull,            /* Null pointer parameter */
    shaInputTooLong,    /* input data too long */
    shaStateError,      /* called Input after FinalBits or Result */
    shaBadParam         /* passed a bad parameter */
};
#endif /* _SHA_enum_ */

/*
 *  These constants hold size information for each of the SHA
 *  hashing operations
 */
enum {
    SHA512_Message_Block_Size = 128,
    USHA_Max_Message_Block_Size = SHA512_Message_Block_Size,

    SHA512HashSize = 64,
    USHAMaxHashSize = SHA512HashSize,


    SHA512HashSizeBits = 512, USHAMaxHashSizeBits = SHA512HashSizeBits
};

/*
 *  These constants are used in the USHA (Unified SHA) functions.
 */
typedef enum SHAversion {
    SHA512
} SHAversion;

/*
 *  This structure will hold context information for the SHA-512
 *  hashing operation.
 * STACKSIZE: ~216B
 */
typedef struct SHA512Context {
#ifdef USE_32BIT_ONLY
    uint32_t Intermediate_Hash[SHA512HashSize/4]; /* Message Digest  */
    uint32_t Length[4];                 /* Message length in bits */
#else /* !USE_32BIT_ONLY */
    uint64_t Intermediate_Hash[SHA512HashSize/8]; /* Message Digest */
    uint64_t Length_High, Length_Low;   /* Message length in bits */
#endif /* USE_32BIT_ONLY */

    int_least16_t Message_Block_Index;  /* Message_Block array index */
                                        /* 1024-bit message blocks */
    uint8_t Message_Block[SHA512_Message_Block_Size];

    uint32_t Computed;                   /* Is the hash computed?*/
    uint32_t Corrupted;                  /* Cumulative corruption code */
} SHA512Context;


/*
 *  This structure holds context information for all SHA
 *  hashing operations.
 */
// STACKSIZE: ~140B
typedef struct USHAContext {
    uint32_t whichSha;               /* which SHA is being used */
    union {
      SHA512Context sha512Context;
    } ctx;

} USHAContext;

/*
 *  This structure will hold context information for the HMAC
 *  keyed-hashing operation.
 * STACKSIZE: ~188B
 */
typedef struct HMACContext {
    uint32_t whichSha;               /* which SHA is being used */
    uint32_t hashSize;               /* hash size of SHA being used */
    uint32_t blockSize;              /* block size of SHA being used */
    USHAContext shaContext;     /* SHA context */
    uint8_t k_opad[USHA_Max_Message_Block_Size];
                        /* outer padding - key XORd with opad */
    uint32_t Computed;               /* Is the MAC computed? */
    uint32_t Corrupted;              /* Cumulative corruption code */

} HMACContext;

/*
 *  This structure will hold context information for the HKDF
 *  extract-and-expand Key Derivation Functions.
 */
typedef struct HKDFContext {
    uint32_t whichSha;               /* which SHA is being used */
    HMACContext hmacContext;
    uint32_t hashSize;               /* hash size of SHA being used */
    uint8_t prk[USHAMaxHashSize];
                        /* pseudo-random key - output of hkdfInput */
    uint32_t Computed;               /* Is the key material computed? */
    uint32_t Corrupted;              /* Cumulative corruption code */
} HKDFContext;

/*
 *  Function Prototypes
 */

/* SHA-512 */
extern uint32_t SHA512Reset(SHA512Context *);
extern uint32_t SHA512Input(SHA512Context *, const uint8_t *bytes,
                      uint32_t bytecount);
extern uint32_t SHA512FinalBits(SHA512Context *, uint8_t bits,
                          uint32_t bit_count);
extern uint32_t SHA512Result(SHA512Context *,
                        uint8_t Message_Digest[SHA512HashSize]);

/* Unified SHA functions*/
extern uint32_t USHAReset(USHAContext *context);
extern uint32_t USHAInput(USHAContext *context,
                     const uint8_t *bytes,uint32_t bytecount);
extern uint32_t USHAFinalBits(USHAContext *context,
                         uint8_t bits,uint32_t bit_count);
extern uint32_t USHAResult(USHAContext *context,
                      uint8_t Message_Digest[USHAMaxHashSize]);
extern const uint32_t USHABlockSize;
extern const uint32_t USHAHashSize;
extern const uint32_t USHAHashSizeBits;
extern const char *USHAHashName;

/*
 * HMAC Keyed-Hashing for Message Authentication, RFC 2104,
 * for all SHAs.
 * This interface allows a fixed-length text input to be used.
 */
extern int32_t hmac(
    const uint8_t *text,     /* pointer to data stream */
    int32_t text_len,                  /* length of data stream */
    const uint8_t *key,      /* pointer to authentication key */
    int32_t key_len,                   /* length of authentication key */
    uint8_t digest[USHAMaxHashSize]); /* caller digest to fill in */


/*
 * HMAC Keyed-Hashing for Message Authentication, RFC 2104,
 * for all SHAs.
 * This interface allows any length of text input to be used.
 */

extern int32_t hmacReset(HMACContext *context,
                     const uint8_t *key, int32_t key_len);
extern int32_t hmacInput(HMACContext *context, const uint8_t *text,
                     int32_t text_len);
extern int32_t hmacFinalBits(HMACContext *context, uint8_t bits,
                         uint32_t bit_count);
extern int32_t hmacResult(HMACContext *context,
                      uint8_t digest[USHAMaxHashSize]);


/*
 * HKDF HMAC-based Extract-and-Expand Key Derivation Function,
 * RFC 5869, for all SHAs.
 */
extern uint32_t hkdf(const uint8_t *salt,
                uint32_t salt_len, const uint8_t *ikm, uint32_t ikm_len,
                const uint8_t *info, uint32_t info_len,
                uint8_t okm[ ], uint32_t okm_len);
extern uint32_t hkdfExtract(const uint8_t *salt,
                       int32_t salt_len, const uint8_t *ikm,
                       uint32_t ikm_len, uint8_t prk[USHAMaxHashSize]);
extern uint32_t hkdfExpand(const uint8_t prk[ ],
                      uint32_t prk_len, const uint8_t *info,
                      int32_t info_len, uint8_t okm[ ], uint32_t okm_len);
#endif /* _SHA_H_ */