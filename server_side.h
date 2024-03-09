// ******************************************************************
// ----------------- TECHNICAL UNIVERSITY OF KOSICE -----------------
// ---Department of Electronics and Multimedia Telecommunications ---
// -------- FACULTY OF ELECTRICAL ENGINEERING AND INFORMATICS -------
// ------------ THIS CODE IS A PART OF A MASTER'S THESIS ------------
// ------------------------- Master thesis --------------------------
// -----------------Patrik Zelenak & Milos Drutarovsky --------------
// ---------------------------version 1.0.1 -------------------------
// --------------------------- 09-03-2024 ---------------------------
// ******************************************************************

/**
  * Empty for now.
**/




#ifndef _SERVER_SIDE_H
#define _SERVER_SIDE_H

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


void ServerRegistrationResponse(
    RegistrationResponse *response,
    const RegistrationRequest *request,
    const uint8_t server_public_key[Npk],
    const uint8_t *credential_identifier, const uint32_t credential_identifier_len,
    const uint8_t oprf_seed[Nh]
  );

void ServerGenerateKE2(
    KE2 *ke2_raw,
    ServerState *state_raw,
    const uint8_t *server_identity, const uint32_t server_identity_len,
    const uint8_t server_private_key[32],
    const uint8_t server_public_key[32],
    const RegistrationRecord *record_raw,
    const uint8_t *credential_identifier, const uint32_t credential_identifier_len,
    const uint8_t oprf_seed[Nh],
    const KE1 *ke1_raw,
    const uint8_t *client_identity, const uint32_t client_identity_len,
    const uint8_t *context, const uint32_t context_len
  );

uint8_t ServerFinish(
    uint8_t session_key[Nx],
    const ServerState *state,
    const KE3 *ke3
  );
#endif // _SERVER_SIDE_H