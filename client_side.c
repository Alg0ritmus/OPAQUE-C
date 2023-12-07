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


#include "client_side.h"

/**
  * This file serves as client-side code for OPAQUE (client) 
  * protocol and contains code necessary for running
  * client-sever communication.
**/


/**
  * First step: offline registration:
  * this file contains function for:
  *       1) registration request -> RegistrationRequest()
  *       2) record -> RegistrationRecord()
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
  *  - password, an opaque byte string containing the client's password.
  *  
  *  Output:
  *  - request, a RegistrationRequest structure.
  *  - blind, an OPRF scalar value.
  *  
  *  Exceptions:
  *  - InvalidInputError, when Blind fails
  *  
  *  def CreateRegistrationRequest(password):
  *    (blind, blinded_element) = Blind(password)
  *    blinded_message = SerializeElement(blinded_element)
  *    Create RegistrationRequest request with blinded_message
  *    return (request, blind)
  *
**/

void ClientRegistrationRequest(
    uint8_t blind[32], 
    RegistrationRequest *request, 
    uint8_t* password, int password_len
  ) {
  rnd(blind, 32);

  CreateRegistrationRequestWithBlind(blind, request, password, password_len);
}



/**
  * FinalizeRegistrationRequest
  * 
  * Input:
  * - password, an opaque byte string containing the client's password.
  * - blind, an OPRF scalar value.
  * - response, a RegistrationResponse structure.
  * - server_identity, the optional encoded server identity.
  * - client_identity, the optional encoded client identity.
  * 
  * Output:
  * - record, a RegistrationRecord structure.
  * - export_key, an additional client key.
  * 
  * Exceptions:
  * - DeserializeError, when OPRF element deserialization fails.
  * 
  * def FinalizeRegistrationRequest(password, blind, response, server_identity, client_identity):
  *   evaluated_element = DeserializeElement(response.evaluated_message)
  *   oprf_output = Finalize(password, blind, evaluated_element)
  * 
  *   stretched_oprf_output = Stretch(oprf_output)
  *   randomized_password = Extract("", concat(oprf_output, stretched_oprf_output))
  * 
  *   (envelope, client_public_key, masking_key, export_key) =
  *     Store(randomized_password, response.server_public_key,
  *           server_identity, client_identity)
  *   Create RegistrationRecord record with (client_public_key, masking_key, envelope)
  *   return (record, export_key)
  *
**/



void ClientRegistrationRecord(
   RegistrationRecord *record,
   uint8_t export_key[Nh],
   uint8_t* password, int password_len,
   uint8_t blind[32],
   RegistrationResponse *response,
   uint8_t *server_identity, int server_identity_len,
   uint8_t *client_identity, int client_identity_len
  ) {

  FinalizeRegistrationRequest(
    record,
    export_key,
    password, password_len,
    blind,
    response,
    server_identity, server_identity_len,
    client_identity, client_identity_len
  );
}



/**
  *
  *      Client                                         Server
  *   ------------------------------------------------------
  *    ke1 = GenerateKE1(password)
  *                           ke1
  *                ------------------------->
  *    ke2 = GenerateKE2(server_identity, server_private_key,
  *                      server_public_key, record,
  *                      credential_identifier, oprf_seed, ke1)
  *                           ke2
  *                <-------------------------
  *      (ke3,
  *      session_key,
  *      export_key) = GenerateKE3(client_identity,
  *                                 server_identity, ke2)
  *                           ke3
  *                ------------------------->
  *                         session_key = ServerFinish(ke3) 
**/


/**
  * 
  * The GenerateKE1 function begins the AKE protocol and produces the
  *   client's KE1 output for the server.
  *
  *   GenerateKE1
  *
  *   State:
  *   - state, a ClientState structure.
  *
  *   Input:
  *   - password, an opaque byte string containing the client's password.
  *
  *   Output:
  *   - ke1, a KE1 message structure.
  *
  *   def GenerateKE1(password):
  *     request, blind = CreateCredentialRequest(password)
  *     state.password = password
  *     state.blind = blind
  *     ke1 = AuthClientStart(request)
  *     return ke1
**/

void ClientGenerateKE1(
    KE1 *ke1,
    ClientState *state,
    uint8_t *password, int password_len
  ) {

  uint8_t blind[32];
  uint8_t client_nonce[32];
  uint8_t seed[Nseed];

  rnd(blind,32);
  rnd(client_nonce,32);
  rnd(seed,Nseed);

  GenerateKE1(
    ke1,
    state,
    password, password_len,
    blind,
    client_nonce,
    seed
  );
}


/**
  *
  * State:
  * - state, a ClientState structure.
  * 
  * Input:
  * - client_identity, the optional encoded client identity, which is set
  *   to client_public_key if not specified.
  * - server_identity, the optional encoded server identity, which is set
  *   to server_public_key if not specified.
  * - ke2, a KE2 message structure.
  * 
  * Output:
  * - ke3, a KE3 message structure.
  * - session_key, the session's shared secret.
  * - export_key, an additional client key.
  * 
  * def GenerateKE3(client_identity, server_identity, ke2):
  *   (client_private_key, cleartext_credentials, export_key) =
  *     RecoverCredentials(state.password, state.blind, ke2.credential_response,
  *                        server_identity, client_identity)
  *   (ke3, session_key) =
  *     AuthClientFinalize(cleartext_credentials, client_private_key, ke2)
  *   return (ke3, session_key, export_key)
**/

void ClientGenerateKE3(
    KE3 *ke3_raw,
    uint8_t session_key[64], // client_session_key
    uint8_t export_key[64],
    ClientState *state,
    const uint8_t *client_identity, const int client_identity_len,
    const uint8_t *server_identity, const int server_identity_len,
    const KE2 *ke2,
    const uint8_t *context, const int context_len
  ) {
  ecc_opaque_ristretto255_sha512_GenerateKE3(
    ke3_raw,
    session_key,
    export_key,
    state, //client state, from ClientGenerateKE1
    client_identity, client_identity_len,
    server_identity, server_identity_len,
    ke2,
    context, context_len
  );
}
