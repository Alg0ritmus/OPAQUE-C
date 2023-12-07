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




#ifndef _SERVER_SIDE_H
#define _SERVER_SIDE_H

#include <stdio.h>
#include <stddef.h>
#include <string.h> 
#include "dependencies/sha.h"

#include "ristretto255/ristretto255.h"
#include "ristretto255/helpers.h"
#include "ristretto255/utils.h"

#include "oprf.h"
#include "opaque.h"
#include "rnd.h"


void ServerRegistrationResponse(
    RegistrationResponse *response,
    RegistrationRequest *request,
    uint8_t server_public_key[Npk],
    uint8_t *credential_identifier, int credential_identifier_len,
    uint8_t oprf_seed[Nh]
  );

void ServerGenerateKE2(
    KE2 *ke2_raw,
    ServerState *state_raw,
    const uint8_t *server_identity, const int server_identity_len,
    const uint8_t server_private_key[32],
    const uint8_t server_public_key[32],
    const RegistrationRecord *record_raw,
    const uint8_t *credential_identifier, const int credential_identifier_len,
    const uint8_t oprf_seed[Nh],
    const KE1 *ke1_raw,
    const uint8_t *client_identity, const int client_identity_len,
    const uint8_t *context, const int context_len
  );

int ServerFinish(
    uint8_t session_key[Nx],
    ServerState *state,
    const KE3 *ke3
  );
#endif // _SERVER_SIDE_H