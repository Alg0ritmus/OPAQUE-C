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
  * Empty for now.
**/

#ifndef _OPAQUE_H
#define _OPAQUE_H

#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <math.h> // for expand_message_xmd_sha512
#include "dependencies/sha.h"
#include "ristretto255/ristretto255.h"
#include "ristretto255/helpers.h"
#include "ristretto255/utils.h"
#include "ristretto255/modl.h"
#include "oprf.h"
#include "rnd.h"

#define Nh 64
#define Npk 32
#define Nsk 32
#define Nm 64
#define Nx 64
#define Nok 32
#define Nn 32
#define Nseed 32

#define unsigned int uint_t
#define IDENTITY_BYTE_SIZE 65535 // <1; 2^16-1> // QUESTION, is it correct?, if not change CreateCleartextCredentials()

struct Envelope{
   uint8_t  nonce[Nn];     // randomly-sampled nonce, used to protect this Envelope
   uint8_t auth_tag[Nm];  // auth tag protecting the contents of the envelope, covering the envelope nonce and CleartextCredentials
 };

void Store(
    struct Envelope *envelope, 
    uint8_t client_public_key[Npk],
    uint8_t masking_key[Nh],
    uint8_t export_key[Nh],
    uint8_t *randomized_password, int randomized_password_len,
    uint8_t server_public_key[Npk],
    uint8_t *server_identity, int server_identity_len,
    uint8_t *client_identity, int client_identity_len
    );



#endif // _CONFIG_H