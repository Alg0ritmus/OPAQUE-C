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

#ifndef _CLIENT_SIDE_H
#define _CLIENT_SIDE_H


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

void ClientRegistrationRequest(
    uint8_t blind[32], 
    RegistrationRequest *request, 
    uint8_t* password, int password_len
  );

void ClientRegistrationRecord(
   RegistrationRecord *record,
   uint8_t export_key[Nh],
   uint8_t* password, int password_len,
   uint8_t blind[32],
   RegistrationResponse *response,
   uint8_t *server_identity, int server_identity_len,
   uint8_t *client_identity, int client_identity_len
  );

void ClientGenerateKE1(
    KE1 *ke1,
    ClientState *state,
    uint8_t *password, int password_len
  );

void ClientGenerateKE3(
    KE3 *ke3_raw,
    uint8_t session_key[64], // client_session_key
    uint8_t export_key[64],
    ClientState *state,
    const uint8_t *client_identity, const int client_identity_len,
    const uint8_t *server_identity, const int server_identity_len,
    const KE2 *ke2,
    const uint8_t *context, const int context_len
  );



#endif // _CLIENT_SIDE_H