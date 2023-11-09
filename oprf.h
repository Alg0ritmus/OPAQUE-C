// ******************************************************************
// ----------------- TECHNICAL UNIVERSITY OF KOSICE -----------------
// ---Department of Electronics and Multimedia Telecommunications ---
// -------- FACULTY OF ELECTRICAL ENGINEERING AND INFORMATICS -------
// ------------ THIS CODE IS A PART OF A MASTER'S THESIS ------------
// ------------------------- Master thesis --------------------------
// -----------------Patrik Zelenak & Milos Drutarovsky --------------
// ---------------------------version 0.0.1 -------------------------
// --------------------------- 11-10-2023 ---------------------------
// ******************************************************************

/**
  * Protocol schema:
  *     Client(input)                                     Server(skS)
  *  ----------------------------------------------------------------
  *  blind, blindedElement = Blind(input)
  *
  *                          blindedElement
  *                            ---------->
  *
  *             evaluatedElement = BlindEvaluate(skS, blindedElement)
  *
  *                          evaluatedElement
  *                            <----------
  *
  *  output = Finalize(input, blind, evaluatedElement)
**/

#ifndef _OPRF_H
#define _OPRF_H

#define Nseed 32 // seed size
#define Npk 32 // key size
#define Nsk 32 // key size
#define Nh 64 //hash digest size
 
int DeterministicDeriveKeyPair(uint8_t skS[Nsk], uint8_t pkS[Npk],uint8_t seed[Nseed], uint8_t *info, int infoLen);
int DeriveKeyPair(uint8_t skS[Nsk], uint8_t pkS[Npk]);
int ecc_voprf_ristretto255_sha512_Blind(uint8_t *blind,uint8_t *blindedElement,uint8_t *input, int inputLen);
int ecc_voprf_ristretto255_sha512_BlindWithScalar(uint8_t *blindedElement, uint8_t *input,  int inputLen, uint8_t *blind);
void BlindEvaluate(uint8_t evaluatedElement[32], uint8_t skS[Nsk], uint8_t blindedElement[32]);
void ScalarMult_(uint8_t outputElement[32], uint8_t scalar[32], uint8_t inputElement[32]);
void Finalize(uint8_t output[Nh],uint8_t* input, int inputLen,uint8_t blind[32], uint8_t evaluatedElement[32]);
void ecc_concat2(
    uint8_t *out,
    const uint8_t *a1, const int a1_len,
    const uint8_t *a2, const int a2_len
);

int expand_message_xmd_sha512(
    uint8_t *out,
    uint8_t *msg, int msgLen,
    uint8_t *DST, int dstLen,
    int len_in_bytes
  );
#endif // _OPRF_H
