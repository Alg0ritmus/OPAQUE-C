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

#define Nh 64
#define Npk 32
#define Nsk 32
#define Nm 64
#define Nx 64
#define Nok 32
#define Nn 32
#define Nseed 32
#define Noe 32
#define Ne 96

// This is an application-
// specific value, e.g., an e-mail address or an account name.  If
// not specified, it defaults to the client/server public key, therefore
// we specified it as 512 bytes to run it without any problems on MCUs
#define IDENTITY_BYTE_SIZE 512


/**
  * OPAQUE STRUCTURES 
  * -----------------
  * OPAQUE uses specific structures, that are implemented in RFC
  * 
  *
**/

// CleartextCredentials structure
typedef struct CleartextCredentials_t{
     uint8_t server_public_key[Npk];
     uint8_t server_identity[IDENTITY_BYTE_SIZE];
     uint32_t server_identity_len;
     uint8_t client_identity[IDENTITY_BYTE_SIZE];
     uint32_t client_identity_len;
   }CleartextCredentials;

typedef struct Envelope_t{
   uint8_t  nonce[Nn];     // randomly-sampled nonce, used to protect this Envelope
   uint8_t auth_tag[Nm];  // auth tag protecting the contents of the envelope, covering the envelope nonce and CleartextCredentials
 }Envelope;


// REGISTRATION MSGs
typedef struct RegistrationRequest_t{
  uint8_t blinded_message[Noe];
} RegistrationRequest;


typedef struct RegistrationResponse_t{
  uint8_t evaluated_message[Noe];
  uint8_t server_public_key[Npk];
} RegistrationResponse;


typedef struct RegistrationRecord_t{
  uint8_t client_public_key[Npk];
  uint8_t masking_key[Nh];
  Envelope envelope;
} RegistrationRecord;

// LOGIN MSGs

typedef struct CredentialRequest_t{
  uint8_t blinded_message[Noe];
} CredentialRequest;


typedef struct CredentialResponse_t{
  uint8_t evaluated_message[Noe];
  uint8_t masking_nonce[Nn];
  uint8_t masked_response[Npk + Nn + Nm];
} CredentialResponse;

typedef struct AuthRequest_t{
  uint8_t client_nonce[Nn];
  uint8_t client_public_keyshare[Npk];
} AuthRequest;


typedef struct KE1_t{
  CredentialRequest credential_request;
  AuthRequest auth_request;
} KE1;

typedef struct AuthResponse_t{
  uint8_t server_nonce[Nn];
  uint8_t server_public_keyshare[Npk];
  uint8_t server_mac[Nm];
} AuthResponse;

typedef struct KE2_t{
  CredentialResponse credential_response;
  AuthResponse auth_response;
} KE2;

typedef struct KE3_t{
  uint8_t client_mac[Nm];
} KE3;


typedef struct ClientAkeState_t{
    uint8_t client_secret[Nsk];
    KE1 ke1;
} ClientAkeState;

typedef struct ClientState_t{
    uint8_t password[512];
    uint32_t password_len;
    uint8_t blind[Nok];
    ClientAkeState client_ake_state;
} ClientState;

typedef struct ServerState_t{
    uint8_t expected_client_mac[Nm];
    uint8_t session_key[Nx];
} ServerState;

// High level Functions

void GenerateKE1(
  KE1 *ke1,
  ClientState *state,
  
  const uint8_t *password, const uint32_t password_len,
  const uint8_t blind[32],
  const uint8_t client_nonce[32],
  const uint8_t seed[Nseed]);

uint32_t ecc_opaque_ristretto255_sha512_GenerateKE3(
    KE3 *ke3_raw,
    uint8_t session_key[64], // client_session_key
    uint8_t export_key[64], // 64
    ClientState *state,
    const uint8_t *client_identity, const uint32_t client_identity_len,
    const uint8_t *server_identity, const uint32_t server_identity_len,
    const KE2 *ke2,
    const uint8_t *context, const uint32_t context_len
);

#endif // _CONFIG_H