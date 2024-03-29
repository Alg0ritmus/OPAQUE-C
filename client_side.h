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

/**
  * Empty for now.
**/

#ifndef _CLIENT_SIDE_H
#define _CLIENT_SIDE_H


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

void ClientRegistrationRequest(
    uint8_t blind[32], 
    RegistrationRequest *request, 
    const uint8_t* password, const uint32_t password_len
  );

void ClientRegistrationRecord(
   RegistrationRecord *record,
   uint8_t export_key[Nh],
   const uint8_t* password, const uint32_t password_len,
   const uint8_t blind[32],
   const RegistrationResponse *response,
   const uint8_t *server_identity, const uint32_t server_identity_len,
   const uint8_t *client_identity, const uint32_t client_identity_len
  );

void ClientGenerateKE1(
    KE1 *ke1,
    ClientState *state,
    const uint8_t *password, const uint32_t password_len
  );

void ClientGenerateKE3(
    KE3 *ke3_raw,
    uint8_t session_key[64], // client_session_key
    uint8_t export_key[64],
    ClientState *state,
    const uint8_t *client_identity, const uint32_t client_identity_len,
    const uint8_t *server_identity, const uint32_t server_identity_len,
    const KE2 *ke2,
    const uint8_t *context, const uint32_t context_len
  );



#endif // _CLIENT_SIDE_H