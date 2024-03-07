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

#include "importer.h"

// SERVER side

// Variables that the server already has:
//  - uint8_t server_private_key[32];
//  - uint8_t server_public_key[32];
//  - uint8_t *server_identity;
//  - int server_identity_len;
//  - uint8_t client_identity;
//  - int client_identity_len;
//  - uint8_t *credential_identifier;
//  - uint8_t *oprf_seed;
//  - KE1 *ke1;
//  - uint8_t *context;
//  - int context_len;
//  - RegistrationRecord record;


// Variables that the server generates in this phase:
//  - KE2 *ke2;
//  - ServerState *state_raw;


int main()
{ 
/**
  * This file focuses more on generating 2. AKE message.
  * KE2 is generated on server-side and is a bit more
  * complicated to explain in detail, since a lot is going
  * on in the background (implementationally-wise). Process
  * starts with ServerGenerateKE2() function.
  *
**/
  

  // 2.2) GenerateKE2
  ServerGenerateKE2(
    &ke2,
    &state_raw,
    server_identity, server_identity_len,
    server_private_key,
    server_public_key,
    &record,
    credential_identifier, credential_identifier_len,
    oprf_seed,
    &ke1,
    client_identity, client_identity_len,
    context, context_len
  );

/**
  * Generate KE2 message by server in detail:
  * -----------------------------------------
  * Input:
  *   - server_identity, the optional encoded server identity, which is set to
  *     server_public_key if not specified.
  *   - server_private_key, the server's private key.
  *   - server_public_key, the server's public key.
  *   - record, the client's RegistrationRecord structure.
  *   - credential_identifier, an identifier that uniquely represents the credential.
  *   - oprf_seed, the server-side seed of Nh bytes used to generate an oprf_key.
  *   - ke1, a KE1 message structure.
  *   - client_identity, the optional encoded client identity, which is set to
  *     client_public_key if not specified.
  *
  * Output:
  *   - ke2, a KE2 structure.
  *
  * Pseudocode of GenerateKE2()
  * -------------------------------
  *
  *   def GenerateKE2(server_identity, server_private_key, server_public_key,
  *                  record, credential_identifier, oprf_seed, ke1, client_identity):
  *     credential_response = CreateCredentialResponse(ke1.credential_request, server_public_key, record,
  *       credential_identifier, oprf_seed)
  *     cleartext_credentials = CreateCleartextCredentials(server_public_key,
  *                         record.client_public_key, server_identity, client_identity)
  *     auth_response = AuthServerRespond(cleartext_credentials, server_private_key,
  *                         record.client_public_key, ke1, credential_response)
  *     Create KE2 ke2 with (credential_response, auth_response)
  *     return ke2
  *
  * As naming suggests CreateCredentialResponse in GenerateKE2 create Credantial response from
  * server, which structure is following:
  *
  * struct{
  *   uint8_t evaluated_message[Noe];
  *   uint8_t masking_nonce[Nn]; // by server - randomly generated < L
  *   uint8_t masked_response[Npk + Nn + Nm];
  * } CredentialResponse;
  *
  * CreateCleartextCredentials works in few steps:
  *
  *     1.) seed = hkdfExpand(credential_identifier || "OprfKey") 
  *     2.) generate  oprf_key based on seed
  *     3.) multiply: evaluated_message = blinded_message (sent by Clinet in KE1) * oprf_key (scaler computed before)
  *
  *     ----- Note that until now it is very similar to steps in section 2.2 during offline registration----
  *
  *     4.) create masking_key = hkdfExpand(masking_nonce || "CredentialResponsePad")
  *     5.) create masked_response =  server_public_key XOR Envelope  // Envelope acqired from client's KE1
  *
  * Other half of GenerateKE2 function is acctual part of AKE protocol using "AuthServerRespond()".
  * AuthServerRespond constists of these steps:
  *
  *   1.) generate server_secret_key and server_keyshare_key
  *   2.) construct preamble = "OPAQUEv1-" || len(context) || context
  *   || len(client_identity) || client_identity || ke1
  *   || len(server_identity) || server_identity
  *   || KE2
  *
  *   3.) TripleDHIKM simply returns ikm (input key material):
  *     3.1) dh1 = sk1 * pk1    // server_secret_key * client_public_keyshare
  *       3.2) dh2 = sk2 * pk2    // server_private_key * client_public_keyshare
  *       3.3) dh3 = sk3 * pk3    // server_secret_key * client_public_key
  *       3.4) ikm = dh1 || dh2 || dh3
  *
  *       Note that sks and pks are input values.
  *
  *      4.) Derive km2, km3, session_key keys from preamble and ikm
  *      - basically this is nothing else than usage of hkdfExtract and hkdmExpand multiple time:
  *
  *       4.1) prk = hkdfExtract(ikm)
  *
  *       4.2) create hash of preamble, preamble_hash = Hash(preamble)
  *
  *       4.3) handshake_secret = hkdfExpand(prk,Nx || preamble_secret_label_len || "OPAQUE-" || preamble_secret_label || preamble_hash_len || preamble_hash);
  *
  *       4.4) session_key = hkdfExpand(prk, Nx || 10 || "OPAQUE-" || "SessionKey" || preamble_hash_len || preamble_hash)
  *
  *       4.5) km2 = hkdfExpand(handshake_secret, Nx || 9 || "OPAQUE-" || "ServerMAC" || 0 || NULL);
  *
  *       4.6) km3 = hkdfExpand(handshake_secret, Nx || 9 || "OPAQUE-" || "ClientMAC" || 0 || NULL);
  *     
  *      5.) calculate server mac:
  *       server_mac = hmac(Km2, Hash(preamble))
  *
  *      6.) calculate expected client mac:
  *       expected_client_mac = hmac(Km3, Hash(preamble || server_mac))
  *
  *
  *     struct {
  *     uint8_t evaluated_message[Noe];       // by CreateCredentialResponse()
  *     uint8_t masking_nonce[Nn];        // by CreateCredentialResponse()
  *     uint8_t masked_response[Npk + Nn + Nm]; // by CreateCredentialResponse()
  *   } CredentialResponse;
  *
  *     struct {
  *     uint8_t server_nonce[Nn];         // random < L
  *     uint8_t server_public_keyshare[Npk];    // from AuthServerRespond()
  *     uint8_t server_mac[Nm];         // from AuthServerRespond()
  *   } AuthResponse;
  *
  *   struct {
  *     CredentialResponse credential_response;
  *     AuthResponse auth_response;
  *   } KE2;
  *
  *   struct {
  *       uint8_t expected_client_mac[Nm];    // from AuthServerRespond()
  *       uint8_t session_key[Nx];        // from AuthServerRespond()
  *   } ServerState;
**/
  return 0;
}