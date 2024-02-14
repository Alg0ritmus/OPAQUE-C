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
 
extern const uint8_t RISTRETTO255_BASEPOINT_OPRF[32];

uint32_t DeterministicDeriveKeyPair(uint8_t skS[Nsk], uint8_t pkS[Npk],uint8_t seed[Nseed], uint8_t *info, uint32_t infoLen);
size_t DeriveKeyPair(uint8_t skS[Nsk], uint8_t pkS[Npk]);
size_t ecc_voprf_ristretto255_sha512_Blind(
    uint8_t *blind,
    uint8_t *blindedElement,
    uint8_t *input, uint32_t inputLen
);
size_t ecc_voprf_ristretto255_sha512_BlindWithScalar(
    uint8_t *blindedElement,
    const  uint8_t *input, const uint32_t inputLen,
    const uint8_t *blind
);
void BlindEvaluate(uint8_t evaluatedElement[32], const uint8_t skS[Nsk], const uint8_t blindedElement[32]);
void ScalarMult_(uint8_t outputElement[32], const uint8_t scalar[32], const uint8_t inputElement[32]);
void Finalize(
    uint8_t output[Nh],
    const uint8_t* input, const uint32_t inputLen,
    const uint8_t blind[32], const uint8_t evaluatedElement[32]
  );
uint32_t cmp(const uint8_t *a, const uint8_t *b, uint32_t size);// returns 1 if they are eq, otherwise 0
void ecc_concat2(
    uint8_t *out,
    const uint8_t *a1, const uint32_t a1_len,
    const uint8_t *a2, const uint32_t a2_len
);


void ecc_concat3(
    uint8_t *out,
    const uint8_t *a1, const uint32_t a1_len,
    const uint8_t *a2, const uint32_t a2_len,
    const uint8_t *a3, const uint32_t a3_len
);

uint32_t expand_message_xmd_sha512(
    uint8_t *out,
    uint8_t *msg, uint32_t msgLen,
    uint8_t *DST, uint32_t dstLen,
    uint32_t len_in_bytes
  );

void ecc_strxor(uint8_t *out, const uint8_t *a, const uint8_t *b, const int32_t len);

void ecc_I2OSP(uint8_t *out, uint64_t x, const int32_t xLen);


#endif // _OPRF_H
