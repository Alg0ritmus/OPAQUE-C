// ******************************************************************
// ----------------- TECHNICAL UNIVERSITY OF KOSICE -----------------
// ---Department of Electronics and Multimedia Telecommunications ---
// -------- FACULTY OF ELECTRICAL ENGINEERING AND INFORMATICS -------
// ------------ THIS CODE IS A PART OF A MASTER'S THESIS ------------
// ------------------------- Master thesis --------------------------
// -----------------Patrik Zelenak & Milos Drutarovsky --------------
// ---------------------------version 1.0.0 -------------------------
// --------------------------- 07-03-2024 ---------------------------
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

#define IDENTITY_BYTE_SIZE 65535 // <1; 2^16-1> // QUESTION, is it correct?, if not change CreateCleartextCredentials()


// opaque function return values 
#define OPAQUE_OK 1
#define OPAQUE_ERROR 0

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
  uint8_t masking_key[Nh]; // prevent enumeration attacks on server-side
  Envelope envelope; // nonce, 
} RegistrationRecord; //auth_tag

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
  uint8_t client_nonce[Nn]; // (rng)
  uint8_t client_public_keyshare[Npk]; // derived from rng seed
} AuthRequest;


typedef struct KE1_t{
  CredentialRequest credential_request; // blinded_msg
  AuthRequest auth_request; //client_nonce, client_public_key from rng seed
} KE1;

typedef struct AuthResponse_t{
  uint8_t server_nonce[Nn];
  uint8_t server_public_keyshare[Npk];
  uint8_t server_mac[Nm];
} AuthResponse;

typedef struct KE2_t{                                                              // credential_resp_pad = Envelope->masking_key XOR masking_nonce||envelope
  CredentialResponse credential_response; //evaluated_message, masking_nonce(rng), masked_response(credential_resp_pad oxr (server_pub_key || envelope))
  AuthResponse auth_response; // server_nonce(rng), server_public_keyshare, server_mac
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

// Low level Functions

/**
  * @brief Creation of Envelope on client during registration phase
  * @param[in]   -> randomized_password -> random pass of variable length? (QUESTION: is it really random length) ?
  * @param[in]   -> server_public_key   -> the encoded server public key for the AKE protocol
  * @param[in]   -> server_identity     -> the optional encoded server identity
  * @param[in]   -> client_identity     -> the optional encoded client identity
  * @param[out]  -> envelope            -> the client's Envelope structure
  * @param[out]  -> client_public_key   -> the client's AKE public key
  * @param[out]  -> masking_key         -> an encryption key used by the server with the sole purpose of defending against client enumeration attacks
  * @param[out]  -> export_key          -> an additional client key
**/ 
void Store(
    Envelope *envelope, 
    uint8_t client_public_key[Npk],
    uint8_t masking_key[Nh],
    uint8_t export_key[Nh],
    const uint8_t *randomized_password, const uint32_t randomized_password_len,
    const uint8_t server_public_key[Npk],
    const uint8_t *server_identity, const uint32_t server_identity_len,
    const uint8_t *client_identity, const uint32_t client_identity_len
    );

uint32_t Recover(
    uint8_t client_private_key[Npk],
    CleartextCredentials *cleartext_credentials,
    uint8_t export_key[Nh],

    uint8_t *randomized_password, uint32_t randomized_password_len,
    uint8_t server_public_key[Npk],
    Envelope *envelope, 
    uint8_t *server_identity, uint32_t server_identity_len,
    uint8_t *client_identity, uint32_t client_identity_len
  );

// High level Functions


// registratoin 
void CreateRegistrationRequestWithBlind( 
    const uint8_t blind[32], 
    RegistrationRequest *request, 
    const uint8_t* password, const uint32_t password_len
  );

void CreateRegistrationResponse(
    RegistrationResponse *response,
    const RegistrationRequest *request,
    const uint8_t server_public_key[Npk],
    const uint8_t *credential_identifier, const uint32_t credential_identifier_len,
    const uint8_t oprf_seed[Nh]
    );

void FinalizeRegistrationRequest(
   RegistrationRecord *record,
   uint8_t export_key[Nh],
   const uint8_t* password, const uint32_t password_len,
   const uint8_t blind[32],
   const RegistrationResponse *response,
   const uint8_t *server_identity, const uint32_t server_identity_len,
   const uint8_t *client_identity, const uint32_t client_identity_len
  );


// login

void GenerateKE1(
  KE1 *ke1,
  ClientState *state,
  
  const uint8_t *password, const uint32_t password_len,
  const uint8_t blind[32],
  const uint8_t client_nonce[32],
  const uint8_t seed[Nseed]);



void ecc_opaque_ristretto255_sha512_GenerateKE2WithSeed(
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
    const uint8_t *context, const uint32_t context_len,
    const uint8_t masking_nonce[Nn],
    const uint8_t server_nonce[Nn],
    const uint8_t seed[Nseed]
);


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


uint32_t ecc_opaque_ristretto255_sha512_ServerFinish(
    uint8_t session_key[Nx],
    const ServerState *state,
    const KE3 *ke3
);

#endif // _CONFIG_H