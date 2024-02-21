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

// P.Z. A lot of features was removed to use just whats
// needed for MCU tests.

#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <math.h> // for expand_message_xmd_sha512
#include "dependencies/sha.h"
#include "ristretto255/ristretto255.h"
#include "ristretto255/helpers.h"
#include "ristretto255/utils.h"
#include "ristretto255/modl.h"
#include "ristretto255/prng.h"
#include "oprf.h"


#define MAXINFOSIZE 1024*5

#define ecc_h2c_expand_message_xmd_sha512_MAXSIZE 16320

#define ecc_h2c_expand_message_xmd_sha512_DSTMAXSIZE 255

const uint8_t ZERO_OPRF[32] = {
    0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0
  };

const uint8_t RISTRETTO255_BASEPOINT_OPRF[32] = {
        0xe2, 0xf2, 0xae, 0xa, 
        0x6a, 0xbc, 0x4e, 0x71, 
        0xa8, 0x84, 0xa9, 0x61,
        0xc5, 0x0,  0x51, 0x5f,
        0x58, 0xe3, 0xb,  0x6a, 
        0xa5, 0x82, 0xdd, 0x8d, 
        0xb6, 0xa6, 0x59, 0x45, 
        0xe0, 0x8d, 0x2d, 0x76
    };

/**
  * This file, serves as lightweight implementation of 
  * OPRF protocol (version 0x00) defined in RFC document:
  * https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-21.html
  * Note that we do not need to implement all function needed for
  * OPRF protocol, we need to extraxt just a few functions. 
  * These functions are implemented in this file and are used 
  * in our OPAQUE implementation (see opaque.c).  
  *
  * In order to impelent OPRF (oblivious pseudorandom function)
  * We needed to implement I2OSP, which is basic conversion of
  * inteeger to bigendian byte-array of variable length.
  * https://www.rfc-editor.org/rfc/rfc8017.
  *------------------------------------------------
  *
  *
  *
  *
  *
  *
**/

// https://github.com/aldenml/ecc/blob/fedffd5624db6d90c659864c21be0c530484c925/src/voprf.c#L34
void ecc_I2OSP(uint8_t *out, uint64_t x, const int32_t xLen) {
    for (int32_t i = xLen - 1; i >= 0; i--) {
        out[i] = x & 0xff;
        x = x >> 8;
    }
}


void ecc_strxor(uint8_t *out, const uint8_t *a, const uint8_t *b, const int32_t len) {
    for (int32_t i = 0; i < len; i++) {
        out[i] = a[i] ^ b[i];
    }
}

void ecc_concat2(
    uint8_t *out,
    const uint8_t *a1, const uint32_t a1_len,
    const uint8_t *a2, const uint32_t a2_len
) {
    memcpy(out, a1, (size_t) a1_len); out += a1_len;
    memcpy(out, a2, (size_t) a2_len);
}


void ecc_concat3(
    uint8_t *out,
    const uint8_t *a1, const uint32_t a1_len,
    const uint8_t *a2, const uint32_t a2_len,
    const uint8_t *a3, const uint32_t a3_len
) {
    memcpy(out, a1, (size_t) a1_len); out += a1_len;
    memcpy(out, a2, (size_t) a2_len); out += a2_len;
    memcpy(out, a3, (size_t) a3_len);
}


// compare 2 arrays of same size
// returns 1 if they are eq, otherwise 0
uint32_t cmp(const uint8_t *a, const uint8_t *b, uint32_t size){
  uint32_t result = 1;
  for (uint32_t i = 0; i < size; ++i) {
    result &= a[i] == b[i];
  }
  return result;
}


// STATIC FUNC

static uint32_t createContextString(
    uint8_t *contextString,
    const uint32_t mode,
    const uint8_t *prefix,
    const uint32_t prefixLen
) {
    // contextString = "OPRFV1-" || I2OSP(mode, 1) || "-" || identifier

    uint8_t id[6] = "OPRFV1";
    uint8_t identifier[19] = "ristretto255-SHA512";
    uint8_t dash[1] = "-";

    uint8_t *p = contextString;

    if (prefix != NULL) {
        ecc_concat2(p, prefix, prefixLen, NULL, 0);
        p += prefixLen;
    }

    ecc_concat2(p, id, sizeof id, dash, 1);
    p += sizeof id + 1;
    ecc_I2OSP(p, mode, 1);
    p += 1;
    ecc_concat2(p, dash, 1, identifier, sizeof identifier);
    p += 1 + sizeof identifier;

    return (int)(p - contextString);
}




// we need hash to group for oprf 
// we need hash to scalar for oprf
// https://github.com/aldenml/ecc/blob/fedffd5624db6d90c659864c21be0c530484c925/src/voprf.c#L1364


// for this we need: ecc_h2c_expand_message_xmd_sha512
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#page-20
// https://github.com/aldenml/ecc/blob/fedffd5624db6d90c659864c21be0c530484c925/src/h2c.c#L152
// Test Vect:
// https://github.com/aldenml/ecc/blob/fedffd5624db6d90c659864c21be0c530484c925/test/data/h2c/expand_message_xmd_sha512.json


static uint32_t expand_message_xmd_sha512(
    uint8_t *out,
    uint8_t *msg, uint32_t msgLen,
    uint8_t *DST, uint32_t dstLen,
    uint32_t len_in_bytes
  ) {
  // Steps:
  //  1.  ell = ceil(len_in_bytes / b_in_bytes)
  //  2.  ABORT if ell > 255 or len_in_bytes > 65535 or len(DST) > 255
  //  3.  DST_prime = DST || I2OSP(len(DST), 1)
  //  4.  Z_pad = I2OSP(0, s_in_bytes)
  //  5.  l_i_b_str = I2OSP(len_in_bytes, 2)
  //  6.  msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime
  //  7.  b_0 = H(msg_prime)
  //  8.  b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
  //  9.  for i in (2, ..., ell):
  //  10.    b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
  //  11. uniform_bytes = b_1 || ... || b_ell
  //  12. return substr(uniform_bytes, 0, len_in_bytes)

  const uint32_t b_in_bytes = 64; // output of Hash function in bytes SHA512 -> 64 bytes
  const uint32_t s_in_bytes = 128;
  uint8_t tmp[1];
  SHA512Context mySha512;
  
  // 1. ell = ceil(len_in_bytes / b_in_bytes)
  //const int ellf = ceil((double) len_in_bytes / b_in_bytes);
  //const int ell = (int) ellf;
  uint32_t ellf = len_in_bytes / b_in_bytes;
  if ((len_in_bytes % b_in_bytes)>0){ellf+=1;}
  const uint32_t ell = ellf;
  

  // 2.
  if (ell>255 || len_in_bytes > 65535 || dstLen>255) {
    return -1;
  }

  // NOTE: to avoid concatenation we need to pass inputs in proper order
  
  // Z_pad = I2OSP(0, s_in_bytes)
  uint8_t Z_pad[s_in_bytes]; // this si eq. to I2OSP(0, s_in_bytes)
  memset(Z_pad,0,s_in_bytes);

  // l_i_b_str = I2OSP(len_in_bytes, 2)
  uint8_t l_i_b_str[2] = {0,0};
  ecc_I2OSP(l_i_b_str,len_in_bytes,2);

  // b_0 = H(msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime)

  uint8_t b_0[64];
  uint8_t b_1[512];
  SHA512Reset(&mySha512);
  SHA512Input(&mySha512,Z_pad,s_in_bytes);
  SHA512Input(&mySha512,msg,msgLen);
  SHA512Input(&mySha512,l_i_b_str,2);
  ecc_I2OSP(tmp, 0, 1);
  SHA512Input(&mySha512,tmp,1);
  SHA512Input(&mySha512,DST,dstLen); // DST_prime below
  ecc_I2OSP(tmp,dstLen, 1);
  SHA512Input(&mySha512,tmp,1);
  SHA512Result(&mySha512, b_0);

  // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)

  SHA512Reset(&mySha512);
  SHA512Input(&mySha512,b_0,64);
  ecc_I2OSP(tmp,1,1);
  SHA512Input(&mySha512,tmp,1);

  SHA512Input(&mySha512,DST,dstLen); // DST_prime below
  ecc_I2OSP(tmp,dstLen, 1);
  SHA512Input(&mySha512,tmp,1);

  SHA512Result(&mySha512, b_1);

  uint8_t uniform_bytes[ecc_h2c_expand_message_xmd_sha512_MAXSIZE];
  memset(uniform_bytes,0,ecc_h2c_expand_message_xmd_sha512_MAXSIZE);
  // To avoid temp variables and concatination we're using
  // uniform_bytes buffer, note that proper order of elements 
  // is cucial. Also we can possibly avoid using uniform_bytes
  // buffer to avoid stack growth by using nested Hash.

  memcpy(uniform_bytes, b_1, 64);
  for (uint32_t i = 2; i <= ell; i++) {
      uint8_t *b_prev = &uniform_bytes[(i - 2) * 64]; // b_(i - 1)
      uint8_t *b_curr = &uniform_bytes[(i - 1) * 64]; // b_i
      SHA512Reset(&mySha512);
      // strxor(b_0, b_(i - 1))
      uint8_t bxor[64];
      ecc_strxor(bxor, b_0, b_prev, 64);
      SHA512Input(&mySha512,bxor,64);
      // I2OSP(i, 1)
      ecc_I2OSP(tmp, i, 1);
      SHA512Input(&mySha512,tmp,1);
      // DST_prime
      //  - DST     
      SHA512Input(&mySha512,DST,dstLen); // DST_prime below
      ecc_I2OSP(tmp,dstLen, 1);
      SHA512Input(&mySha512,tmp,1);
      SHA512Result(&mySha512, b_curr);
  }
  memcpy(out, uniform_bytes, (size_t)len_in_bytes);

  // DONT FORGET TO CLEAN UP STACK!

  return 1;


}



static void ecc_voprf_ristretto255_sha512_HashToGroupWithDST(
    uint8_t *out,
    const uint8_t *input, const uint32_t inputLen,
    const uint8_t *dst, const uint32_t dstLen
) {
    uint8_t expand_message[64];
    expand_message_xmd_sha512(expand_message, (uint8_t*) input, inputLen, (uint8_t*) dst, dstLen, 64);

    hash_to_group(out, expand_message);

    // stack memory cleanup

}


static void ecc_voprf_ristretto255_sha512_HashToGroup(
    uint8_t *out,
    const uint8_t *input, const uint32_t inputLen
) {
    uint8_t DST[100];
    uint8_t DSTPrefix[12] = "HashToGroup-";
    const uint32_t DSTLen = createContextString(
        DST, 0,
        DSTPrefix, sizeof DSTPrefix
    );

    ecc_voprf_ristretto255_sha512_HashToGroupWithDST(out, input, inputLen, DST, DSTLen);
}


static void ecc_voprf_ristretto255_sha512_HashToScalarWithDST(
    uint8_t *out,
    const uint8_t *input, const uint32_t inputLen,
    const uint8_t *dst, const uint32_t dstLen
) {
    uint8_t expand_message[64];
    expand_message_xmd_sha512(expand_message, (uint8_t*) input, inputLen, (uint8_t*) dst, dstLen, 64);

    
    uint32_t tmp[16];
    // tmp <- expand_message

    memcpy(tmp, expand_message, 64); 

    mod_l(out, tmp);

    // stack memory cleanup
 
}


static void ecc_voprf_ristretto255_sha512_HashToScalar(
    uint8_t *out,
    const uint8_t *input, const uint32_t inputLen
) {
    uint8_t DST[100];
    uint8_t DSTPrefix[13] = "HashToScalar-";
    const uint32_t DSTsize = createContextString(
        DST, 0,
        DSTPrefix, sizeof DSTPrefix
    );

    ecc_voprf_ristretto255_sha512_HashToScalarWithDST(out, input, inputLen, DST, DSTsize);
}

// END OF STARTIC FUNC BLOCK


#if 1 // test
// https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-21.html#section-3.2.1
uint32_t DeterministicDeriveKeyPair(
    uint8_t skS[Nsk], uint8_t pkS[Npk],
    uint8_t seed[Nseed], uint8_t *info, uint32_t infoLen
  ) {

  // add infoLen constrain
  if (infoLen>MAXINFOSIZE) {
    return -1;

  }
  uint8_t deriveInput[2048];
  
  // deriveInput = seed || I2OSP(len(info), 2) || info
  // For non-heap allocation, we created a long buffer called
  // 'deriveInput[2048].' We simply track the size of individual
  // elements that we insert into 'deriveInput' and then insert
  // another element by pointing to another address in the
  // 'deriveInput' buffer.
  uint8_t deriveInputLen = 0;
  ecc_concat2(&deriveInput[deriveInputLen], seed, Nseed, NULL, 0);
  deriveInputLen += Nseed;
  ecc_I2OSP(&deriveInput[deriveInputLen], infoLen, 2);
  deriveInputLen += 2;
  ecc_concat2(&deriveInput[deriveInputLen], info, infoLen, NULL, 0);
  deriveInputLen += infoLen;

  uint32_t counter = 0; //possibly uint8_t or size_t
  //sKs = 0
  memset(skS, 0, Nsk);
  uint8_t DST[100];
  uint8_t DSTPrefix[13] = "DeriveKeyPair";
  const uint8_t DSTsize = createContextString(
      DST,
      0,
      DSTPrefix, sizeof DSTPrefix
  );


  uint8_t input[2048];
  while (cmp(skS,ZERO_OPRF,Nsk)){
    if (counter > 255){return -1;}; //DeriveKeyPairError
      
    //hash to scalar -> hashToGroup in ristretto255 mod L
    uint8_t inputLen = 0;
    ecc_concat2(&input[inputLen], deriveInput, deriveInputLen, NULL, 0);
    inputLen += deriveInputLen;
    ecc_I2OSP(&input[inputLen], counter, 1);
    inputLen += 1;

    // skS = G.HashToScalar(deriveInput || I2OSP(counter, 1), DST = "DeriveKeyPair" || contextString)
    //hash_to_group(skS,output);
    ecc_voprf_ristretto255_sha512_HashToScalarWithDST(skS,input,inputLen,DST,DSTsize);

    counter+=1;
  }

  // pkS = G.ScalarMultGen(skS)
  ScalarMult_(pkS,skS,(uint8_t*)RISTRETTO255_BASEPOINT_OPRF);
  return 1;
}

//https://www.rfc-editor.org/rfc/rfc9380.html#name-expand_message
// expand_message_xmd(msg, DST, len_in_bytes) ?? treba asi ci ?

#endif // test
// https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-21.html#name-oprf-protocol
int32_t ecc_voprf_ristretto255_sha512_BlindWithScalar(
    uint8_t *blindedElement,
    const  uint8_t *input, const uint32_t inputLen,
    const uint8_t *blind
) {
    uint8_t inputElement[32];
    ecc_voprf_ristretto255_sha512_HashToGroup(inputElement, input, inputLen);
    if (cmp(inputElement,ZERO_OPRF,Nsk)){return -1;}
    ScalarMult_(blindedElement, blind, inputElement);

    // stack memory cleanup
    crypto_wipe(inputElement, sizeof inputElement);


    return 1;
}


// input/output elem are ristretto255 elems in 32 byte form
void ScalarMult_(uint8_t outputElement[32], const uint8_t scalar[32], const uint8_t inputElement[32]){
  ristretto255_point output_ristretto_point;
  ristretto255_point *out_rist = &output_ristretto_point;
  ristretto255_point output_ristretto_point2;
  ristretto255_point *out_rist2 = &output_ristretto_point2;

  ristretto255_decode(out_rist,inputElement);
  ristretto255_scalarmult(out_rist2, out_rist, scalar);
  ristretto255_encode(outputElement,out_rist2);
}

void Finalize(
    uint8_t output[Nh],
    const uint8_t* input, const uint32_t inputLen,
    const uint8_t blind[32], const uint8_t evaluatedElement[32]
  ) {

  ristretto255_point output_ristretto_point;
  ristretto255_point *out_rist = &output_ristretto_point;
  
  uint8_t blind_inverse[32];
  uint8_t N[32];
  uint8_t unblindedElement[32];
  uint8_t i2osp1[2];
  uint8_t i2osp2[2];

  // blind^-1
  modl_l_inverse(blind_inverse,blind);

  //N = G.ScalarInverse(blind) * evaluatedElement
  ScalarMult_(N, blind_inverse, evaluatedElement);

  //unblindedElement = G.SerializeElement(N) // ristretto ristretto255_encode // TODO: I think this can be skipped due to decode/encode inside ScalarMult_() function
  ristretto255_decode(out_rist, N);
  ristretto255_encode(unblindedElement, out_rist);
  
  //hash from big secure_concat
  
  uint8_t temp[8] = "Finalize";
  
  ecc_I2OSP(i2osp1, inputLen, 2); // I2OSP(len(input), 2)
  ecc_I2OSP(i2osp2, 32, 2); //I2OSP(len(unblindedElement), 2)

  // hashInput = I2OSP(len(input), 2) || input ||
  //             I2OSP(len(unblindedElement), 2) || unblindedElement ||
  //             "Finalize"
  // Here we avoid concatination just by update of hash.
  SHA512Context mySha512;
  SHA512Reset(&mySha512);
  SHA512Input(&mySha512, i2osp1, 2);
  SHA512Input(&mySha512, input, (unsigned int) inputLen);
  SHA512Input(&mySha512, i2osp2, 2);
  SHA512Input(&mySha512, unblindedElement, 32);
  SHA512Input(&mySha512, temp, 8);
  SHA512Result(&mySha512, output);
}



