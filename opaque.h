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
#define Noe 32
#define Ne 96

//#define unsigned int uint_t
#define IDENTITY_BYTE_SIZE 65535 // <1; 2^16-1> // QUESTION, is it correct?, if not change CreateCleartextCredentials()


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
     int server_identity_len;
     uint8_t client_identity[IDENTITY_BYTE_SIZE];
     int client_identity_len;
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
    int password_len;
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
    uint8_t *randomized_password, int randomized_password_len,
    uint8_t server_public_key[Npk],
    uint8_t *server_identity, int server_identity_len,
    uint8_t *client_identity, int client_identity_len
    );

int Recover(
    uint8_t client_private_key[Npk],
    CleartextCredentials *cleartext_credentials,
    uint8_t export_key[Nh],

    uint8_t *randomized_password, int randomized_password_len,
    uint8_t server_public_key[Npk],
    Envelope *envelope, 
    uint8_t *server_identity, int server_identity_len,
    uint8_t *client_identity, int client_identity_len
  );

// High level Functions


// registratoin 
void CreateRegistrationRequestWithBlind( 
    uint8_t blind[32], 
    RegistrationRequest *request, 
    uint8_t* password, int password_len
  );

void CreateRegistrationResponse(
    RegistrationResponse *response,
    RegistrationRequest *request,
    uint8_t server_public_key[Npk],
    uint8_t *credential_identifier, int credential_identifier_len,
    uint8_t oprf_seed[Nh]
    );

void FinalizeRegistrationRequest(
   RegistrationRecord *record,
   uint8_t export_key[Nh],
   uint8_t* password, int password_len,
   uint8_t blind[32],
   RegistrationResponse *response,
   uint8_t *server_identity, int server_identity_len,
   uint8_t *client_identity, int client_identity_len
  );


// login

void GenerateKE1(
  KE1 *ke1,
  ClientState *state,
  
  uint8_t *password, int password_len,
  uint8_t blind[32],
  uint8_t client_nonce[32],
  uint8_t seed[Nseed]);



void ecc_opaque_ristretto255_sha512_GenerateKE2WithSeed(
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
    const uint8_t *context, const int context_len,
    const uint8_t masking_nonce[Nn],
    const uint8_t server_nonce[Nn],
    const uint8_t seed[Nseed]
);


int ecc_opaque_ristretto255_sha512_GenerateKE3(
    KE3 *ke3_raw,
    uint8_t session_key[64], // client_session_key
    uint8_t export_key[64], // 64
    ClientState *state,
    const uint8_t *client_identity, const int client_identity_len,
    const uint8_t *server_identity, const int server_identity_len,
    const KE2 *ke2,
    const uint8_t *context, const int context_len
);


int ecc_opaque_ristretto255_sha512_ServerFinish(
    uint8_t session_key[Nx],
    ServerState *state,
    const KE3 *ke3
);

#endif // _CONFIG_H