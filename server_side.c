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

#include "server_side.h"


/**
  * This file serves as client-side code for OPAQUE (client) 
  * protocol and contains code necessary for running
  * client-sever communication.
**/


/**
  * First step: offline registration:
  * this file contains function for:
  *       1) registration response -> RegistrationResponse()
  * --------------------------------------------------
  *    creds                                   parameters
  *      |                                         |
  *      v                                         v
  *    Client                                    Server
  *    ------------------------------------------------
  *                registration request
  *             ------------------------->
  *                registration response
  *             <-------------------------
  *                      record
  *             ------------------------->
  *   ------------------------------------------------
  *      |                                         |
  *      v                                         v
  *  export_key                                 record
**/



/**
  * Input:
  * - request, a RegistrationRequest structure.
  * - server_public_key, the server's public key.
  * - credential_identifier, an identifier that uniquely represents the credential.
  * - oprf_seed, the seed of Nh bytes used by the server to generate an oprf_key.
  * 
  * Output:
  * - response, a RegistrationResponse structure.
  * 
  * Exceptions:
  * - DeserializeError, when OPRF element deserialization fails.
  * - DeriveKeyPairError, when OPRF key derivation fails.
  * 
  * def CreateRegistrationResponse(request, server_public_key,
  *                                credential_identifier, oprf_seed):
  *   seed = Expand(oprf_seed, concat(credential_identifier, "OprfKey"), Nok)
  *   (oprf_key, _) = DeriveKeyPair(seed, "OPAQUE-DeriveKeyPair")
  * 
  *   blinded_element = DeserializeElement(request.blinded_message)
  *   evaluated_element = BlindEvaluate(oprf_key, blinded_element)
  *   evaluated_message = SerializeElement(evaluated_element)
  * 
  *   Create RegistrationResponse response with (evaluated_message, server_public_key)
  *   return response
**/


void ServerRegistrationResponse(
    RegistrationResponse *response,
    RegistrationRequest *request,
    uint8_t server_public_key[Npk],
    uint8_t *credential_identifier, int credential_identifier_len,
    uint8_t oprf_seed[Nh]
  ) {

  CreateRegistrationResponse(
    response,
    request,
    server_public_key,
    credential_identifier, credential_identifier_len,
    oprf_seed
  );

}


/**
  * State:
  * - state, a ServerState structure.
  * 
  * Input:
  * - server_identity, the optional encoded server identity, which is set to
  *   server_public_key if not specified.
  * - server_private_key, the server's private key.
  * - server_public_key, the server's public key.
  * - record, the client's RegistrationRecord structure.
  * - credential_identifier, an identifier that uniquely represents the credential.
  * - oprf_seed, the server-side seed of Nh bytes used to generate an oprf_key.
  * - ke1, a KE1 message structure.
  * - client_identity, the optional encoded client identity, which is set to
  *   client_public_key if not specified.
  * 
  * Output:
  * - ke2, a KE2 structure.
  * 
  * def GenerateKE2(server_identity, server_private_key, server_public_key,
  *                record, credential_identifier, oprf_seed, ke1, client_identity):
  *   credential_response = CreateCredentialResponse(ke1.credential_request, server_public_key, record,
  *     credential_identifier, oprf_seed)
  *   cleartext_credentials = CreateCleartextCredentials(server_public_key,
  *                       record.client_public_key, server_identity, client_identity)
  *   auth_response = AuthServerRespond(cleartext_credentials, server_private_key,
  *                       record.client_public_key, ke1, credential_response)
  *   Create KE2 ke2 with (credential_response, auth_response)
  *   return ke2
**/
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
  ) {

    uint8_t masking_nonce[Nn];
    uint8_t server_nonce[Nn];
    uint8_t server_keyshare_seed[Nseed];

    rnd(masking_nonce,Nn);
    rnd(server_nonce,Nn);
    rnd(server_keyshare_seed,Nseed);

  ecc_opaque_ristretto255_sha512_GenerateKE2WithSeed(
    ke2_raw,
    state_raw,
    server_identity, server_identity_len,
    server_private_key,
    server_public_key,
    record_raw,
    credential_identifier, credential_identifier_len,
    oprf_seed,
    ke1_raw,
    client_identity, client_identity_len,
    context, context_len,
    masking_nonce,
    server_nonce,
    server_keyshare_seed
  );
}


// if -1, error occured
// else 0, success
int ServerFinish(
    uint8_t session_key[Nx],
    ServerState *state,
    const KE3 *ke3
  ) {

  int result = 0;
  result = ecc_opaque_ristretto255_sha512_ServerFinish(
    session_key,
    state, //server state from KE2
    ke3
  );

  return result;
}

