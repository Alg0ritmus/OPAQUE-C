// ******************************************************************
// ----------------- TECHNICAL UNIVERSITY OF KOSICE -----------------
// ---Department of Electronics and Multimedia Telecommunications ---
// -------- FACULTY OF ELECTRICAL ENGINEERING AND INFORMATICS -------
// ------------ THIS CODE IS A PART OF A MASTERS THESIS ------------
// ------------------------- Master thesis --------------------------
// -----------------Patrik Zelenak & Milos Drutarovsky --------------
// ---------------------------version 0.0.1 -------------------------
// --------------------------- 14-10-2023 ---------------------------
// ******************************************************************

/*
 * This file serves for testing purposes; it compares the results of 
 * each OPAQUE main function against official test vectors.
*/

#include <stdio.h>
#include <stddef.h>
#include <string.h> 
#include "dependencies/sha.h"

#include "ristretto255/ristretto255.h"
#include "ristretto255/helpers.h"
#include "ristretto255/utils.h"
#include "ristretto255/prng.h"

#include "oprf.h"
#include "opaque.h"


// inputs

uint8_t blind_login[32] = {
    0x6e, 0xcc, 0x10, 0x2d, 0x2e, 0x7a, 0x7c, 0xf4,
    0x96, 0x17, 0xaa, 0xd7, 0xbb, 0xe1, 0x88, 0x55,
    0x67, 0x92, 0xd4, 0xac, 0xd6, 0x0a, 0x1a, 0x8a,
    0x8d, 0x2b, 0x65, 0xd4, 0xb0, 0x79, 0x03, 0x08
};

uint8_t blind_registration[32] = {
    0x76, 0xcf, 0xbf, 0xe7, 0x58, 0xdb, 0x88, 0x4b,
    0xeb, 0xb3, 0x35, 0x82, 0x33, 0x1b, 0xa9, 0xf1,
    0x59, 0x72, 0x0c, 0xa8, 0x78, 0x4a, 0x2a, 0x07,
    0x0a, 0x26, 0x5d, 0x9c, 0x2d, 0x6a, 0xbe, 0x01
};

uint8_t client_identity[0] = {};
uint32_t client_identity_len=0;

uint8_t client_keyshare_seed[32]=  {
    0x82, 0x85, 0x0a, 0x69, 0x7b, 0x42, 0xa5, 0x05, 
    0xf5, 0xb6, 0x8f, 0xcd, 0xaf, 0xce, 0x8c, 0x31, 
    0xf0, 0xaf, 0x2b, 0x58, 0x1f, 0x06, 0x3c, 0xf1, 
    0x09, 0x19, 0x33, 0x54, 0x19, 0x36, 0x30, 0x4b
  };

uint8_t client_nonce[32] = {
    0xda, 0x7e, 0x07, 0x37, 0x6d, 0x6d, 0x6f, 0x03,
    0x4c, 0xfa, 0x9b, 0xb5, 0x37, 0xd1, 0x1b, 0x8c,
    0x6b, 0x42, 0x38, 0xc3, 0x34, 0x33, 0x3d, 0x1f,
    0x0a, 0xeb, 0xb3, 0x80, 0xca, 0xe6, 0xa6, 0xcc
};

uint8_t credential_identifier[4] = {0x31, 0x32, 0x33, 0x34};

uint8_t envelope_nonce[32] = {
    0xac, 0x13, 0x17, 0x1b, 0x2f, 0x17, 0xbc, 0x2c,
    0x74, 0x99, 0x7f, 0x0f, 0xce, 0x1e, 0x1f, 0x35,
    0xbe, 0xc6, 0xb9, 0x1f, 0xe2, 0xe1, 0x2d, 0xbd,
    0x32, 0x3d, 0x23, 0xba, 0x7a, 0x38, 0xdf, 0xec
};

uint8_t masking_nonce[32] = {
    0x38, 0xfe, 0x59, 0xaf, 0x0d, 0xf2, 0xc7, 0x9f,
    0x57, 0xb8, 0x78, 0x02, 0x78, 0xf5, 0xae, 0x47,
    0x35, 0x5f, 0xe1, 0xf8, 0x17, 0x11, 0x90, 0x41,
    0x95, 0x1c, 0x80, 0xf6, 0x12, 0xfd, 0xfc, 0x6d
};

uint8_t oprf_seed[64] = {
     0xf4, 0x33, 0xd0, 0x22, 0x7b, 0x0b, 0x9d, 0xd5,
     0x4f, 0x7c, 0x44, 0x22, 0xb6, 0x00, 0xe7, 0x64,
     0xe4, 0x7f, 0xb5, 0x03, 0xf1, 0xf9, 0xa0, 0xf0,
     0xa4, 0x7c, 0x66, 0x06, 0xb0, 0x54, 0xa7, 0xfd,
     0xc6, 0x53, 0x47, 0xf1, 0xa0, 0x8f, 0x27, 0x7e,
     0x22, 0x35, 0x8b, 0xba, 0xbe, 0x26, 0xf8, 0x23,
     0xfc, 0xa8, 0x2c, 0x78, 0x48, 0xe9, 0xa7, 0x56,
     0x61, 0xf4, 0xec, 0x5d, 0x5c, 0x19, 0x89, 0xef
};

uint8_t password[25] = {0x43, 0x6f, 0x72, 0x72, 0x65, 0x63, 0x74, 0x48, 0x6f, 0x72, 0x73, 0x65, 0x42, 0x61, 0x74, 0x74, 0x65, 0x72, 0x79, 0x53, 0x74, 0x61, 0x70, 0x6c, 0x65};
uint32_t password_len = 25;

uint8_t server_identity[0] = {};
uint32_t server_identity_len = 0;

uint8_t server_keyshare_seed[32] = {
    0x05, 0xa4, 0xf5, 0x42, 0x06, 0xee, 0xf1, 0xba,
    0x2f, 0x61, 0x5b, 0xc0, 0xaa, 0x28, 0x5c, 0xb2,
    0x2f, 0x26, 0xd1, 0x15, 0x3b, 0x5b, 0x40, 0xa1,
    0xe8, 0x5f, 0xf8, 0x0d, 0xa1, 0x2f, 0x98, 0x2f
};

uint8_t server_nonce[32] = {
    0x71, 0xcd, 0x99, 0x60, 0xec, 0xef, 0x2f, 0xe0,
    0xd0, 0xf7, 0x49, 0x49, 0x86, 0xfa, 0x3d, 0x8b,
    0x2b, 0xb0, 0x19, 0x63, 0x53, 0x7e, 0x60, 0xef,
    0xb1, 0x39, 0x81, 0xe1, 0x38, 0xe3, 0xd4, 0xa1
};

uint8_t server_private_key[32] = {
    0x47, 0x45, 0x1a, 0x85, 0x37, 0x2f, 0x8b, 0x35,
    0x37, 0xe2, 0x49, 0xd7, 0xb5, 0x41, 0x88, 0x09,
    0x1f, 0xb1, 0x8e, 0xdd, 0xe7, 0x80, 0x94, 0xb4,
    0x3e, 0x2b, 0xa4, 0x2b, 0x5e, 0xb8, 0x9f, 0x0d
};

uint8_t server_public_key[32] = {
    0xb2, 0xfe, 0x7a, 0xf9, 0xf4, 0x8c, 0xc5, 0x02,
    0xd0, 0x16, 0x72, 0x9d, 0x2f, 0xe2, 0x5c, 0xdd,
    0x43, 0x3f, 0x2c, 0x4b, 0xc9, 0x04, 0x66, 0x0b,
    0x2a, 0x38, 0x2c, 0x9b, 0x79, 0xdf, 0x1a, 0x78
};

uint8_t context[10] = {0x4f, 0x50, 0x41, 0x51, 0x55, 0x45, 0x2d, 0x50, 0x4f, 0x43};

// intermediates values

uint8_t _auth_key[64] = {
    0x6c, 0xd3, 0x23, 0x16, 0xf1, 0x8d, 0x72, 0xa9,
    0xa9, 0x27, 0xa8, 0x31, 0x99, 0xfa, 0x03, 0x06,
    0x63, 0xa3, 0x8c, 0xe0, 0xc1, 0x1f, 0xba, 0xef,
    0x82, 0xaa, 0x90, 0x03, 0x77, 0x30, 0x49, 0x4f,
    0xc5, 0x55, 0xc4, 0xd4, 0x95, 0x06, 0x28, 0x45,
    0x16, 0xed, 0xd1, 0x62, 0x8c, 0x27, 0x96, 0x5b,
    0x75, 0x55, 0xa4, 0xeb, 0xfe, 0xd2, 0x22, 0x31,
    0x99, 0xf6, 0xc6, 0x79, 0x66, 0xdd, 0xe8, 0x22
};

uint8_t _client_mac_key[64] = {
    0x91, 0x75, 0x0a, 0xdb, 0xac, 0x54, 0xa5, 0xe8,
    0xe5, 0x3b, 0x4c, 0x23, 0x3c, 0xc8, 0xd3, 0x69,
    0xfe, 0x83, 0xb0, 0xde, 0x1b, 0x6a, 0x3c, 0xd8,
    0x55, 0x75, 0xee, 0xb0, 0xbb, 0x01, 0xa6, 0xa9,
    0x0a, 0x08, 0x6a, 0x2c, 0xf5, 0xfe, 0x75, 0xff,
    0xf2, 0xa9, 0x37, 0x9c, 0x30, 0xba, 0x90, 0x49,
    0x51, 0x0a, 0x33, 0xb5, 0xb0, 0xb1, 0x44, 0x4a,
    0x88, 0x80, 0x0f, 0xc3, 0xee, 0xe2, 0x26, 0x0d
};

uint8_t _client_public_key[32] = {
    0x76, 0xa8, 0x45, 0x46, 0x4c, 0x68, 0xa5, 0xd2,
    0xf7, 0xe4, 0x42, 0x43, 0x6b, 0xb1, 0x42, 0x49,
    0x53, 0xb1, 0x7d, 0x3e, 0x2e, 0x28, 0x9c, 0xcb,
    0xac, 0xca, 0xfb, 0x57, 0xac, 0x5c, 0x36, 0x75
};

uint8_t _envelope[96] = {
    0xac, 0x13, 0x17, 0x1b, 0x2f, 0x17,
    0xbc, 0x2c, 0x74, 0x99, 0x7f, 0x0f, 
    0xce, 0x1e, 0x1f, 0x35, 0xbe, 0xc6, 
    0xb9, 0x1f, 0xe2, 0xe1, 0x2d, 0xbd, 
    0x32, 0x3d, 0x23, 0xba, 0x7a, 0x38, 
    0xdf, 0xec, 0x63, 0x4b, 0x0f, 0x5b, 
    0x96, 0x10, 0x9c, 0x19, 0x8a, 0x80, 
    0x27, 0xda, 0x51, 0x85, 0x4c, 0x35, 
    0xbe, 0xe9, 0x0d, 0x1e, 0x1c, 0x78, 
    0x18, 0x06, 0xd0, 0x7d, 0x49, 0xb7, 
    0x6d, 0xe6, 0xa2, 0x8b, 0x8d, 0x9e, 
    0x9b, 0x6c, 0x93, 0xb9, 0xf8, 0xb6, 
    0x4d, 0x16, 0xdd, 0xdd, 0x9c, 0x5b, 
    0xfb, 0x5f, 0xea, 0x48, 0xee, 0x8f, 
    0xd2, 0xf7, 0x50, 0x12, 0xa8, 0xb3, 
    0x08, 0x60, 0x5c, 0xdd, 0x8b, 0xa5
};

uint8_t _handshake_secret[64] = {
    0x81, 0x26, 0x3c, 0xb8, 0x5a, 0x0c, 0xfa, 0x12,
    0x45, 0x0f, 0x0f, 0x38, 0x8d, 0xe4, 0xe9, 0x22,
    0x91, 0xec, 0x4c, 0x7c, 0x7a, 0x08, 0x78, 0xb6,
    0x24, 0x55, 0x0f, 0xf5, 0x28, 0x72, 0x63, 0x32,
    0xf1, 0x29, 0x8f, 0xc6, 0xcc, 0x82, 0x2a, 0x43,
    0x2c, 0x89, 0x50, 0x43, 0x47, 0xc7, 0xa2, 0xcc,
    0xd7, 0x03, 0x16, 0xae, 0x3d, 0xa6, 0xa1, 0x5e,
    0x03, 0x99, 0xe6, 0xdb, 0x3f, 0x7c, 0x1b, 0x12
};

uint8_t _masking_key[64] = {
    0x1a, 0xc5, 0x84, 0x43, 0x83, 0xc7, 0x70, 0x80,
    0x77, 0xde, 0xa4, 0x1c, 0xbe, 0xfe, 0x2f, 0xa1,
    0x57, 0x24, 0xf4, 0x49, 0xe5, 0x35, 0xdd, 0x7d,
    0xd5, 0x62, 0xe6, 0x6f, 0x5e, 0xcf, 0xb9, 0x58,
    0x64, 0xea, 0xdd, 0xde, 0xc9, 0xdb, 0x58, 0x74,
    0x95, 0x99, 0x05, 0x11, 0x7d, 0xad, 0x40, 0xa4,
    0x52, 0x41, 0x11, 0x84, 0x97, 0x99, 0x28, 0x1f,
    0xef, 0xe3, 0xc5, 0x1f, 0xa8, 0x27, 0x85, 0xc5
};

uint8_t _oprf_key[32] = {
    0x5d, 0x4c, 0x6a, 0x8b, 0x7c, 0x71, 0x38, 0x18,
    0x2a, 0xfb, 0x43, 0x45, 0xd1, 0xfa, 0xe6, 0xa9,
    0xf1, 0x8a, 0x17, 0x44, 0xaf, 0xbc, 0xc3, 0x85,
    0x4f, 0x8f, 0x5a, 0x2b, 0x4b, 0x4c, 0x6d, 0x05
};

uint8_t _randomized_password[64] = {
    0xaa, 0xc4, 0x8c, 0x25, 0xab, 0x03, 0x6e, 0x30,
    0x75, 0x08, 0x39, 0xd3, 0x1d, 0x6e, 0x73, 0x00,
    0x73, 0x44, 0xcb, 0x11, 0x55, 0x28, 0x9f, 0xb7,
    0xd3, 0x29, 0xbe, 0xb9, 0x32, 0xe9, 0xad, 0xee,
    0xa7, 0x3d, 0x5d, 0x5c, 0x22, 0xa0, 0xce, 0x19,
    0x52, 0xf8, 0xab, 0xa6, 0xd6, 0x60, 0x07, 0x61,
    0x5c, 0xd1, 0x69, 0x8d, 0x4a, 0xc8, 0x5e, 0xf1,
    0xfc, 0xf1, 0x50, 0x03, 0x1d, 0x14, 0x35, 0xd9
};

uint8_t _server_mac_key[64] = {
    0x0d, 0x36, 0xb2, 0x6c, 0xfe, 0x38, 0xf5, 0x1f,
    0x80, 0x4f, 0x0a, 0x93, 0x61, 0x81, 0x8f, 0x32,
    0xee, 0x1c, 0xe2, 0xa4, 0xe5, 0x57, 0x86, 0x53,
    0xb5, 0x27, 0x18, 0x4a, 0xf0, 0x58, 0xd3, 0xb2,
    0xd8, 0x07, 0x5c, 0x29, 0x6f, 0xd8, 0x4d, 0x24,
    0x67, 0x79, 0x13, 0xd1, 0xba, 0xa1, 0x09, 0x29,
    0x0c, 0xd8, 0x1a, 0x13, 0xed, 0x38, 0x3f, 0x90,
    0x91, 0xa3, 0x80, 0x4e, 0x65, 0x29, 0x8d, 0xfc
};


// outputs

uint8_t _KE1[96] = {
    0xc4, 0xde, 0xdb, 0x0b, 0xa6, 0xed, 0x5d, 0x96, 
    0x5d, 0x6f, 0x25, 0x0f, 0xbe, 0x55, 0x4c, 0xd4, 
    0x5c, 0xba, 0x5d, 0xfc, 0xce, 0x3c, 0xe8, 0x36, 
    0xe4, 0xae, 0xe7, 0x78, 0xaa, 0x3c, 0xd4, 0x4d, 
    0xda, 0x7e, 0x07, 0x37, 0x6d, 0x6d, 0x6f, 0x03, 
    0x4c, 0xfa, 0x9b, 0xb5, 0x37, 0xd1, 0x1b, 0x8c, 
    0x6b, 0x42, 0x38, 0xc3, 0x34, 0x33, 0x3d, 0x1f, 
    0x0a, 0xeb, 0xb3, 0x80, 0xca, 0xe6, 0xa6, 0xcc, 
    0x6e, 0x29, 0xbe, 0xe5, 0x07, 0x01, 0x49, 0x86, 
    0x05, 0xb2, 0xc0, 0x85, 0xd7, 0xb2, 0x41, 0xca, 
    0x15, 0xba, 0x5c, 0x32, 0x02, 0x7d, 0xd2, 0x1b, 
    0xa4, 0x20, 0xb9, 0x4c, 0xe6, 0x0d, 0xa3, 0x26
};

uint8_t _KE2[320] = {
    0x7e, 0x30, 0x81, 0x40, 0x89, 0x0b, 0xcd, 0xe3, 
    0x0c, 0xbc, 0xea, 0x28, 0xb0, 0x1e, 0xa1, 0xec, 
    0xfb, 0xd0, 0x77, 0xcf, 0xf6, 0x2c, 0x4d, 0xef, 
    0x8e, 0xfa, 0x07, 0x5a, 0xab, 0xcb, 0xb4, 0x71, 
    0x38, 0xfe, 0x59, 0xaf, 0x0d, 0xf2, 0xc7, 0x9f, 
    0x57, 0xb8, 0x78, 0x02, 0x78, 0xf5, 0xae, 0x47, 
    0x35, 0x5f, 0xe1, 0xf8, 0x17, 0x11, 0x90, 0x41, 
    0x95, 0x1c, 0x80, 0xf6, 0x12, 0xfd, 0xfc, 0x6d, 
    0xd6, 0xec, 0x60, 0xbc, 0xdb, 0x26, 0xdc, 0x45, 
    0x5d, 0xdf, 0x3e, 0x71, 0x8f, 0x10, 0x20, 0x49, 
    0x0c, 0x19, 0x2d, 0x70, 0xdf, 0xc7, 0xe4, 0x03, 
    0x98, 0x11, 0x79, 0xd8, 0x07, 0x3d, 0x11, 0x46, 
    0xa4, 0xf9, 0xaa, 0x1c, 0xed, 0x4e, 0x4c, 0xd9, 
    0x84, 0xc6, 0x57, 0xeb, 0x3b, 0x54, 0xce, 0xd3, 
    0x84, 0x83, 0x26, 0xf7, 0x03, 0x31, 0x95, 0x3d, 
    0x91, 0xb0, 0x25, 0x35, 0xaf, 0x44, 0xd9, 0xfe, 
    0xdc, 0x80, 0x18, 0x8c, 0xa4, 0x67, 0x43, 0xc5,
    0x27, 0x86, 0xe0, 0x38, 0x2f, 0x95, 0xad, 0x85,
    0xc0, 0x8f, 0x6a, 0xfc, 0xd1, 0xcc, 0xfb, 0xff, 
    0x95, 0xe2, 0xbd, 0xeb, 0x01, 0x5b, 0x16, 0x6c, 
    0x6b, 0x20, 0xb9, 0x2f, 0x83, 0x2c, 0xc6, 0xdf, 
    0x01, 0xe0, 0xb8, 0x6a, 0x7e, 0xfd, 0x92, 0xc1, 
    0xc8, 0x04, 0xff, 0x86, 0x57, 0x81, 0xfa, 0x93, 
    0xf2, 0xf2, 0x0b, 0x44, 0x6c, 0x83, 0x71, 0xb6, 
    0x71, 0xcd, 0x99, 0x60, 0xec, 0xef, 0x2f, 0xe0, 
    0xd0, 0xf7, 0x49, 0x49, 0x86, 0xfa, 0x3d, 0x8b, 
    0x2b, 0xb0, 0x19, 0x63, 0x53, 0x7e, 0x60, 0xef, 
    0xb1, 0x39, 0x81, 0xe1, 0x38, 0xe3, 0xd4, 0xa1, 
    0xc4, 0xf6, 0x21, 0x98, 0xa9, 0xd6, 0xfa, 0x91, 
    0x70, 0xc4, 0x2c, 0x3c, 0x71, 0xf1, 0x97, 0x1b, 
    0x29, 0xeb, 0x1d, 0x5d, 0x0b, 0xd7, 0x33, 0xe4,
    0x08, 0x16, 0xc9, 0x1f, 0x79, 0x12, 0xcc, 0x4a,
    0x66, 0x0c, 0x48, 0xda, 0xe0, 0x3e, 0x57, 0xaa, 
    0xa3, 0x8f, 0x3d, 0x0c, 0xff, 0xcf, 0xc2, 0x18, 
    0x52, 0xeb, 0xc8, 0xb4, 0x05, 0xd1, 0x5b, 0xd6, 
    0x74, 0x49, 0x45, 0xba, 0x1a, 0x93, 0x43, 0x8a, 
    0x16, 0x2b, 0x61, 0x11, 0x69, 0x9d, 0x98, 0xa1,
    0x6b, 0xb5, 0x5b, 0x7b, 0xdd, 0xdf, 0xe0, 0xfc,
    0x56, 0x08, 0xb2, 0x3d, 0xa2, 0x46, 0xe7, 0xbd, 
    0x73, 0xb4, 0x73, 0x69, 0x16, 0x9c, 0x5c, 0x90
};

uint8_t _KE3[64] = {
    0x44, 0x55, 0xdf, 0x4f, 0x81, 0x0a, 0xc3, 0x1a, 
    0x67, 0x48, 0x83, 0x58, 0x88, 0x56, 0x4b, 0x53, 
    0x6e, 0x6d, 0xa5, 0xd9, 0x94, 0x4d, 0xfe, 0xa9, 
    0xe3, 0x4d, 0xef, 0xb9, 0x57, 0x5f, 0xe5, 0xe2, 
    0x66, 0x1e, 0xf6, 0x1d, 0x2a, 0xe3, 0x92, 0x9b, 
    0xcf, 0x57, 0xe5, 0x3d, 0x46, 0x41, 0x13, 0xd3, 
    0x64, 0x36, 0x5e, 0xb7, 0xd1, 0xa5, 0x7b, 0x62, 
    0x97, 0x07, 0xca, 0x48, 0xda, 0x18, 0xe4, 0x42
};

uint8_t _export_key[64] = {
    0x1e, 0xf1, 0x5b, 0x4f, 0xa9, 0x9e, 0x8a, 0x85,
    0x24, 0x12, 0x45, 0x0a, 0xb7, 0x87, 0x13, 0xaa,
    0xd3, 0x0d, 0x21, 0xfa, 0x69, 0x66, 0xc9, 0xb8,
    0xc9, 0xfb, 0x32, 0x62, 0xa9, 0x70, 0xdc, 0x62,
    0x95, 0x0d, 0x4d, 0xd4, 0xed, 0x62, 0x59, 0x82,
    0x29, 0xb1, 0xb7, 0x27, 0x94, 0xfc, 0x03, 0x35,
    0x19, 0x9d, 0x9f, 0x7f, 0xcc, 0x6e, 0xae, 0xdd,
    0xe9, 0x2c, 0xc0, 0x48, 0x70, 0xe6, 0x3f, 0x16
};

uint8_t _registration_request[64] = {
    0x50, 0x59, 0xff, 0x24, 0x9e, 0xb1, 0x55, 0x1b,
    0x7c, 0xe4, 0x99, 0x1f, 0x33, 0x36, 0x20, 0x5b,
    0xde, 0x44, 0xa1, 0x05, 0xa0, 0x32, 0xe7, 0x47,
    0xd2, 0x1b, 0xf3, 0x82, 0xe7, 0x5f, 0x7a, 0x71
};

uint8_t _registration_response[64] = {
    0x74, 0x08, 0xa2, 0x68, 0x08, 0x3e, 0x03, 0xab,
    0xc7, 0x09, 0x7f, 0xc0, 0x5b, 0x58, 0x78, 0x34,
    0x53, 0x90, 0x65, 0xe8, 0x6f, 0xb0, 0xc7, 0xb6,
    0x34, 0x2f, 0xcf, 0x5e, 0x01, 0xe5, 0xb0, 0x19,
    0xb2, 0xfe, 0x7a, 0xf9, 0xf4, 0x8c, 0xc5, 0x02,
    0xd0, 0x16, 0x72, 0x9d, 0x2f, 0xe2, 0x5c, 0xdd,
    0x43, 0x3f, 0x2c, 0x4b, 0xc9, 0x04, 0x66, 0x0b,
    0x2a, 0x38, 0x2c, 0x9b, 0x79, 0xdf, 0x1a, 0x78
};

uint8_t _registration_upload[192] = {
    0x76, 0xa8, 0x45, 0x46, 0x4c, 0x68, 0xa5, 0xd2,
    0xf7, 0xe4, 0x42, 0x43, 0x6b, 0xb1, 0x42, 0x49, 
    0x53, 0xb1, 0x7d, 0x3e, 0x2e, 0x28, 0x9c, 0xcb, 
    0xac, 0xca, 0xfb, 0x57, 0xac, 0x5c, 0x36, 0x75, 
    0x1a, 0xc5, 0x84, 0x43, 0x83, 0xc7, 0x70, 0x80, 
    0x77, 0xde, 0xa4, 0x1c, 0xbe, 0xfe, 0x2f, 0xa1, 
    0x57, 0x24, 0xf4, 0x49, 0xe5, 0x35, 0xdd, 0x7d, 
    0xd5, 0x62, 0xe6, 0x6f, 0x5e, 0xcf, 0xb9, 0x58, 
    0x64, 0xea, 0xdd, 0xde, 0xc9, 0xdb, 0x58, 0x74, 
    0x95, 0x99, 0x05, 0x11, 0x7d, 0xad, 0x40, 0xa4, 
    0x52, 0x41, 0x11, 0x84, 0x97, 0x99, 0x28, 0x1f, 
    0xef, 0xe3, 0xc5, 0x1f, 0xa8, 0x27, 0x85, 0xc5, 
    0xac, 0x13, 0x17, 0x1b, 0x2f, 0x17, 0xbc, 0x2c, 
    0x74, 0x99, 0x7f, 0x0f, 0xce, 0x1e, 0x1f, 0x35, 
    0xbe, 0xc6, 0xb9, 0x1f, 0xe2, 0xe1, 0x2d, 0xbd, 
    0x32, 0x3d, 0x23, 0xba, 0x7a, 0x38, 0xdf, 0xec, 
    0x63, 0x4b, 0x0f, 0x5b, 0x96, 0x10, 0x9c, 0x19, 
    0x8a, 0x80, 0x27, 0xda, 0x51, 0x85, 0x4c, 0x35, 
    0xbe, 0xe9, 0x0d, 0x1e, 0x1c, 0x78, 0x18, 0x06, 
    0xd0, 0x7d, 0x49, 0xb7, 0x6d, 0xe6, 0xa2, 0x8b, 
    0x8d, 0x9e, 0x9b, 0x6c, 0x93, 0xb9, 0xf8, 0xb6, 
    0x4d, 0x16, 0xdd, 0xdd, 0x9c, 0x5b, 0xfb, 0x5f, 
    0xea, 0x48, 0xee, 0x8f, 0xd2, 0xf7, 0x50, 0x12, 
    0xa8, 0xb3, 0x08, 0x60, 0x5c, 0xdd, 0x8b, 0xa5
};

uint8_t _session_key[64] = {
    0x42, 0xaf, 0xde, 0x6f, 0x5a, 0xca, 0x0c, 0xfa, 
    0x5c, 0x16, 0x37, 0x63, 0xfb, 0xad, 0x55, 0xe7, 
    0x3a, 0x41, 0xdb, 0x6b, 0x41, 0xbc, 0x87, 0xb8, 
    0xe7, 0xb6, 0x22, 0x14, 0xa8, 0xee, 0xdc, 0x67, 
    0x31, 0xfa, 0x3c, 0xb8, 0x57, 0xd6, 0x57, 0xab, 
    0x9b, 0x37, 0x64, 0xb8, 0x9a, 0x84, 0xe9, 0x1e, 
    0xbc, 0xb4, 0x78, 0x51, 0x66, 0xfb, 0xb0, 0x2c, 
    0xed, 0xfc, 0xbd, 0xfd, 0xa2, 0x15, 0xb9, 0x6f
};


static uint8_t compare(uint8_t *a, uint8_t *b, size_t count){
  uint8_t result = 1;
  for (size_t i = 0; i < count; i++)
  {
    result &= a[i] == b[i];
  }
  return result;
}

int main(){
  s_rand(1234);

  // -----------------------------------         
  // ------------- TESTING OF ----------
  // --------------- OPAQUE ------------
  // -----------------------------------   

uint8_t test_result = 1;

uint8_t randomized_password[64] = {0xaa,0xc4,0x8c,0x25,0xab,0x03,0x6e,0x30,0x75,0x08,0x39,0xd3,0x1d,0x6e,0x73,0x00,0x73,0x44,0xcb,0x11,0x55,0x28,0x9f,0xb7,0xd3,0x29,0xbe,0xb9,0x32,0xe9,0xad,0xee,0xa7,0x3d,0x5d,0x5c,0x22,0xa0,0xce,0x19,0x52,0xf8,0xab,0xa6,0xd6,0x60,0x07,0x61,0x5c,0xd1,0x69,0x8d,0x4a,0xc8,0x5e,0xf1,0xfc,0xf1,0x50,0x03,0x1d,0x14,0x35,0xd9};
uint32_t randomized_password_len = 64;

  Envelope envelope;
  uint8_t client_public_key[Npk];
  uint8_t masking_key[Nh];
  uint8_t export_key[Nh];

  Store(
      &envelope, 
      client_public_key,
      masking_key,
      export_key,
      randomized_password, randomized_password_len,
      server_public_key,
      server_identity, server_identity_len,
      client_identity, client_identity_len
      );

  
  test_result = compare((uint8_t*)&envelope, _envelope,96);
  if (test_result==0){printf("ERROR: Store->envelope\n");}
  else {printf("SUCCESS: Store->envelope\n");}

  test_result = compare(export_key,_export_key,64);
  if (test_result==0){printf("ERROR: Store->export_key\n");}
  else {printf("SUCCESS: Store->export_key\n");}
  test_result = compare(client_public_key,_client_public_key,32);
  if (test_result==0){printf("ERROR: Store->client_public_key\n");}
  else {printf("SUCCESS: Store->client_public_key\n");}
  test_result = compare(masking_key,_masking_key,64);
  if (test_result==0){printf("ERROR: Store->masking_key\n");}
  else {printf("SUCCESS: Store->masking_key\n");}

  RegistrationRequest request;
  CreateRegistrationRequestWithBlind( 
    blind_registration, 
    &request, 
    password, password_len
  );

  test_result = compare(request.blinded_message,_registration_request,32);
  if (test_result==0){printf("ERROR: CreateRegistrationRequest->blinded_message\n");}
  else {printf("SUCCESS: CreateRegistrationRequest->blinded_message\n");}

  RegistrationResponse response;
  CreateRegistrationResponse(
    &response,
    &request,
    server_public_key,
    credential_identifier, 4,
    oprf_seed
  );

  test_result = compare((uint8_t*) &response,_registration_response,64);
  if (test_result==0){printf("ERROR: CreateRegistrationResponse->response\n");}
  else {printf("SUCCESS: CreateRegistrationResponse->response\n");}

  RegistrationRecord record;
  FinalizeRegistrationRequest(
   &record,
   export_key,
   password, password_len,
   blind_registration,
   &response,
   server_identity, server_identity_len,
   client_identity, client_identity_len
  );

  test_result = compare(export_key,_export_key,64);
  if (test_result==0){printf("ERROR: FinalizeRegistrationRequest->export_key\n");}
  else {printf("SUCCESS: FinalizeRegistrationRequest->export_key\n");}
  test_result = compare((uint8_t*) &record,_registration_upload,192);
  if (test_result==0){printf("ERROR: FinalizeRegistrationRequest->record\n");}
  else {printf("SUCCESS: FinalizeRegistrationRequest->record\n");}

  //////////////////////////
  //  AKE1
  //////

  KE1 ke1;
  ClientState state;

  GenerateKE1(
    &ke1, &state,
    password, password_len,
    blind_login,
    client_nonce,
    client_keyshare_seed
    );

  test_result = compare((uint8_t*) &ke1,_KE1,96);
  if (test_result==0){printf("ERROR: GenerateKE1->KE1\n");}
  else {printf("SUCCESS: GenerateKE1->KE1\n");}
	


  KE2 ke2;
  ServerState state_raw;
  ecc_opaque_ristretto255_sha512_GenerateKE2WithSeed(
    &ke2,
    &state_raw,
    server_identity, server_identity_len,
    server_private_key,
    server_public_key,
    &record,
    credential_identifier, 4,
    oprf_seed,
    &ke1,
    client_identity, client_identity_len,
    context, 10,
    masking_nonce,
    server_nonce,
    server_keyshare_seed
  );

  test_result = compare((uint8_t*) &ke2,_KE2,256);
  if (test_result==0){printf("ERROR: GenerateKE2->KE2\n");}
  else {printf("SUCCESS: GenerateKE2->KE2\n");}

  KE3 ke3;
  uint8_t client_session_key[64];
  ecc_opaque_ristretto255_sha512_GenerateKE3(
    &ke3,
    client_session_key,
    export_key, // 64
    &state, // from KE1
    client_identity, client_identity_len,
    server_identity, server_identity_len,
    &ke2, // from ke2_raw
    context, 10
  );

  test_result = compare((uint8_t*) &ke3,_KE3,64);
  if (test_result==0){printf("ERROR: GenerateKE3->KE3\n");}
  else {printf("SUCCESS: GenerateKE3->KE3\n");}
  test_result = compare(client_session_key,_session_key,64);
  if (test_result==0){printf("ERROR: GenerateKE3->client_session_key\n");}
  {printf("SUCCESS: GenerateKE3->client_session_key\n");}
  test_result = compare(export_key,_export_key,64);
  if (test_result==0){printf("ERROR: GenerateKE3->export_key\n");}
  else {printf("SUCCESS: GenerateKE3->export_key\n");}


  uint8_t session_key[Nx];
  ecc_opaque_ristretto255_sha512_ServerFinish(
    session_key,
    &state_raw, //server state from KE2
    &ke3
  );

  test_result = compare(session_key,_session_key,64);
  if (test_result==0){printf("ERROR: ServerFinish->session_key\n");}
  else{printf("SUCCESS: ServerFinish->session_key\n");}


  printf("TEST RESULT: %d",test_result);
  return 0;

}