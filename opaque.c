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
  * This file contains implemantation of OPAQUE (aPAKE) protocol.
  * NOTE that this implementation should be as closest to RFC
  * implementation as possible, so you should be able to follow
  * all this code with RFC specification and compare it line by line.
  * We're planning to write clean and comperhensive impl. of OPAQUE
  * protocol in C. We are also targetting on MCU platforms (Cortex M-4)
  * so a big part of our design is aimed on peformance, compactness and 
  * small size of impl. Also note that we decided (I decided,
  * but can be changed) that we are using D.1.2.1 configuration of OPAQUE.
  * D.1.2.1 configuration is specified in OPAQUE draft.
  *
  * Offcial RFC used during implemenation creation:
  * https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-12.txt
  *
  * First we'll create first phase of OPAQUE protocol, which is
  * registration part.
  *
  * KEYWORDS:
  *   - TODO:     - means there is something unfinished
  *   - NOTE:     - means there is something worth to pay attention
  *   - QUESTION: - means I'm not so sure about this, consultation needed 
  *
  *
  *     creds                                   parameters
  *       |                                         |
  *       v                                         v
  *     Client                                    Server
  *     ------------------------------------------------
  *                 registration request
  *              ------------------------->
  *                 registration response
  *              <-------------------------
  *                       record
  *              ------------------------->
  *    ------------------------------------------------
  *       |                                         |
  *       v                                         v
  *   export_key                                 record
  *
  *
  *
  *
  *
  *
  *
  *
  *
  *
  *
  *
  *
**/

#include <stdint.h>
#include <string.h>
#include "opaque.h"
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
#include "opaque.h"

/**
  * OPAQUE CONFIGURATION D.1.2.1
  * ----------------------------
  * OPRF: ristretto255-SHA512
  * Hash: SHA512
  * KSF: Identity
  * KDF: HKDF-SHA512 --   -> z toho vytiahnem aj sha mozno cize super len otestuj! ma to aj HMAC!!! aj sha cize vsetko?
  * MAC: HMAC-SHA512
  * Group: ristretto255
  * Context: 4f50415155452d504f43
  * Nh: 64
  * Npk: 32
  * Nsk: 32
  * Nm: 64
  * Nx: 64
  * Nok: 32
**/

/** 
  * @param[in]   -> server_public_key     -> the encoded server public key for the AKE protocol
  * @param[in]   -> client_public_key     -> the client's AKE public key
  * @param[in]   -> server_identity       -> the optional encoded server identity
  * @param[in]   -> client_identity       -> the optional encoded client identity
  * @param[in]   -> server_identity_len       -> server identity lenght
  * @param[in]   -> client_identity_len       -> client identity lenght
  * @param[out]  -> cleartext_credentials -> CleartextCredentials structure
**/

// "Constructor" of CleartextCredentials structure
void CreateCleartextCredentials(
    CleartextCredentials *cleartext_credentials,
    uint8_t server_public_key[Npk],
    uint8_t client_public_key[Npk], // QUESTION: how to propperly indent this ?
    uint8_t server_identity[IDENTITY_BYTE_SIZE], int server_identity_len,
    uint8_t client_identity[IDENTITY_BYTE_SIZE], int client_identity_len
  ) {



  // check if all words/libs in server_identity/client_identity
  // is set to 0, if so we assume that server/client identity
  // is not set, therefore we set default values by draft specs.

  // https://stackoverflow.com/questions/1296843/what-is-the-difference-between-null-0-and-0
  if (server_identity == NULL || server_identity_len == 0) {
        server_identity = server_public_key;
        server_identity_len = Npk;
    }
    if (client_identity == NULL || client_identity_len == 0) {
        client_identity = client_public_key;
        client_identity_len = Npk;
    }

  // set default identities, note that server_identity and server_public_key
  // are equal in length (same for client identity...)
  memcpy(cleartext_credentials->server_public_key, server_public_key, Npk);

  memcpy(cleartext_credentials->server_identity, server_identity, server_identity_len);
  cleartext_credentials->server_identity_len =  server_identity_len;

  memcpy(cleartext_credentials->client_identity, client_identity, client_identity_len);
  cleartext_credentials->client_identity_len = client_identity_len;

}


// https://github.com/aldenml/ecc/blob/fedffd5624db6d90c659864c21be0c530484c925/src/opaque.c#L194C1-L211C2
static int serializeCleartextCredentials(uint8_t *out, CleartextCredentials *credentials) {
    const int len = Npk + 2 + credentials->server_identity_len + 2 + credentials->client_identity_len;
    printf("1.)idzeee: server_identity_len:%d | client_identity_len:%d\n",credentials->server_identity_len,credentials->client_identity_len);

    int offset = 0;
    memcpy(&out[offset], credentials->server_public_key, Npk);
    offset += Npk;
    out[offset + 0] = (credentials->server_identity_len >> 8) & 0xff;
    out[offset + 1] = credentials->server_identity_len & 0xff;
    offset += 2;
    memcpy(&out[offset], credentials->server_identity, credentials->server_identity_len);
    offset += credentials->server_identity_len;
    out[offset + 0] = (credentials->client_identity_len >> 8) & 0xff;
    out[offset + 1] = credentials->client_identity_len & 0xff;
    offset += 2;
    memcpy(&out[offset], credentials->client_identity, credentials->client_identity_len);
    printf("2.)idzeee\n");
    return len;
}


/**
  * Key Recovery
  * ------------
  * This specification defines a key recovery mechanism that uses the
  * stretched OPRF output as a seed to directly derive the private and
  * public keys using the DeriveDiffieHellmanKeyPair() function defined.
  * 
**/
  
//struct Envelope{
//   uint8_t  nonce[Nn];     // randomly-sampled nonce, used to protect this Envelope
//   uint8_t auth_tag[Nm];  // auth tag protecting the contents of the envelope, covering the envelope nonce and CleartextCredentials
// };

/**
  * Clients create an Envelope at registration with the function Store()
  * defined below.  Note that DeriveDiffieHellmanKeyPair in this function
  * can fail with negligible probability.  If this occurs, servers should
  * re-run the function, sampling a new envelope_nonce, to completion.
  *
  *
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

// https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-12.html
void Store(
    Envelope *envelope, 
    uint8_t client_public_key[Npk],
    uint8_t masking_key[Nh],
    uint8_t export_key[Nh],
    uint8_t *randomized_password, int randomized_password_len,
    uint8_t server_public_key[Npk],
    uint8_t *server_identity, int server_identity_len,
    uint8_t *client_identity, int client_identity_len
    ) {



    CleartextCredentials clear_cred; // QUESTION: Can I do it in 1 line?
    CleartextCredentials *cleartext_credentials = &clear_cred; // Do I need this line?


    // QUESTION: we need to use TRNG multiple time here,
    // do we wanna use Cyclone? e.g.
    // https://github.com/Oryx-Embedded/CycloneCRYPTO/blob/master/hardware/ra2/ra2_crypto_trng.c#L51C9-L51C56 
    uint8_t envelope_nonce[Nn] = {0xac, 0x13, 0x17, 0x1b, 0x2f, 0x17, 0xbc, 0x2c, 0x74, 0x99, 0x7f, 0x0f, 0xce, 0x1e, 0x1f, 0x35, 0xbe, 0xc6, 0xb9, 0x1f, 0xe2, 0xe1, 0x2d, 0xbd, 0x32, 0x3d, 0x23, 0xba, 0x7a, 0x38, 0xdf, 0xec};
    
    //rnd(envelope_nonce,0x00);    // envelope_nonce = random(Nn)


 
    // NOTE: that Expand/Extract should be taken from HKDF 
    // https://tools.ietf.org/html/rfc5869

    uint8_t masking_key_info[10] = "MaskingKey";
    uint8_t auth_key_label[7] = "AuthKey";
    uint8_t export_key_label[9] = "ExportKey";
    uint8_t seed_label[10] = "PrivateKey";

    uint8_t auth_key[Nh];
    uint8_t auth_key_info[Nn + 7];
    uint8_t export_key_info[Nn+9];
    uint8_t seed[Nseed];
    uint8_t seed_info[Nn + 10];

    hkdfExpand(SHA512,randomized_password,randomized_password_len, masking_key_info, 10, masking_key, Nh);

    ecc_concat2(auth_key_info, envelope_nonce, Nn, auth_key_label, 7);
    hkdfExpand(SHA512,randomized_password,randomized_password_len, auth_key_info, Nn+7, auth_key, Nh);

    ecc_concat2(export_key_info, envelope_nonce, Nn, export_key_label, 9);
    hkdfExpand(SHA512,randomized_password,randomized_password_len, export_key_info, Nn+9, export_key, Nh);

    ecc_concat2(seed_info, envelope_nonce, Nn, seed_label, 10);
    hkdfExpand(SHA512,randomized_password,randomized_password_len, seed_info, Nn+10, seed, Nseed);

    // 
    uint8_t skS[Nsk];
    uint8_t info[33] = "OPAQUE-DeriveDiffieHellmanKeyPair";
    //DeriveDiffieHellmanKeyPair(seed);


    DeterministicDeriveKeyPair(skS,client_public_key,seed, info, 33);
    // clear skS from stack

    printf("server_identity_len:%d, client_identity_len:%d\n",server_identity_len,client_identity_len );
    CreateCleartextCredentials(
        cleartext_credentials, 
        server_public_key, 
        client_public_key,
        server_identity, server_identity_len, 
        client_identity, client_identity_len
      );

    uint8_t cleartext_creds_buf[512];

    int cleartext_creds_len = serializeCleartextCredentials(
        cleartext_creds_buf,
        cleartext_credentials
    );

   // auth_tag_mac_input = concat(envelope_nonce, cleartext_credentials)
    uint8_t auth_tag_mac_input[Nn+cleartext_creds_len];
    ecc_concat2(
        auth_tag_mac_input,
        envelope_nonce, Nn,
        cleartext_creds_buf, cleartext_creds_len
    );

    hmac(SHA512, auth_tag_mac_input, Nn+cleartext_creds_len, auth_key, Nh, envelope->auth_tag);
    memcpy(envelope->nonce, envelope_nonce, Nn);
}


/**
  * ENVELOPE RECOVER
  *
  * @param[in]  -> randomized_password,     ->    a randomized password.
  * @param[in]  -> server_public_key,       ->    the encoded server public key for the AKE protocol.
  * @param[in]  -> envelope,                ->    the client's Envelope structure.
  * @param[in]  -> server_identity,         ->    the optional encoded server identity.
  * @param[in]  -> client_identity,         ->    the optional encoded client identity.
  * @param[out] -> client_private_key,      ->    the encoded client private key for the AKE protocol.
  * @param[out] -> cleartext_credentials,   ->    a CleartextCredentials structure.
  * @param[out] -> export_key,              ->    an additional client key.
**/
int Recover(
    uint8_t client_private_key[Npk],
    CleartextCredentials *cleartext_credentials,
    uint8_t export_key[Nh],

    uint8_t *randomized_password, int randomized_password_len,
    uint8_t server_public_key[Npk],
    Envelope *envelope, 
    uint8_t *server_identity, int server_identity_len,
    uint8_t *client_identity, int client_identity_len
  ) {
  
    uint8_t auth_key_label[7] = "AuthKey";
    uint8_t export_key_label[9] = "ExportKey";
    uint8_t seed_label[10] = "PrivateKey";

    uint8_t auth_key[Nh];
    uint8_t auth_key_info[Nn + 7];
    uint8_t export_key_info[Nn+9];
    uint8_t seed[Nseed];
    uint8_t seed_info[Nn + 10];    

    //auth_key = Expand(randomized_password, concat(envelope.nonce, "AuthKey"), Nh)
    ecc_concat2(auth_key_info, envelope->nonce, Nn, auth_key_label, 7);
    hkdfExpand(SHA512,randomized_password,randomized_password_len, auth_key_info, Nn+7, auth_key, Nh);

    //export_key = Expand(randomized_password, concat(envelope.nonce, "ExportKey"), Nh)
    ecc_concat2(export_key_info, envelope->nonce, Nn, export_key_label, 9);
    hkdfExpand(SHA512,randomized_password,randomized_password_len, export_key_info, Nn+9, export_key, Nh);

    //seed = Expand(randomized_password, concat(envelope.nonce, "PrivateKey"), Nseed)
    ecc_concat2(seed_info, envelope->nonce, Nn, seed_label, 10);
    hkdfExpand(SHA512,randomized_password,randomized_password_len, seed_info, Nn+10, seed, Nseed);

    //(client_private_key, client_public_key) = DeriveDiffieHellmanKeyPair(seed)
    uint8_t client_public_key[Npk];
    uint8_t info[33] = "OPAQUE-DeriveDiffieHellmanKeyPair";
    int infoLen = 33;
    DeterministicDeriveKeyPair(
        client_private_key,
        client_public_key,
        seed,
        info, infoLen
      ); 

    // cleartext_credentials = CreateCleartextCredentials(
                        // server_public_key, client_public_key, 
                        // server_identity, client_identity)
    CreateCleartextCredentials(
        cleartext_credentials, 
        server_public_key, 
        client_public_key,
        server_identity, server_identity_len, 
        client_identity, client_identity_len
      );


    // expected_tag = MAC(auth_key, concat(envelope.nonce, cleartext_credentials))
    uint8_t cleartext_creds_buf[512];
    
    int cleartext_creds_len = serializeCleartextCredentials(
        cleartext_creds_buf,
        cleartext_credentials
    );

    uint8_t expected_tag[Nn+cleartext_creds_len];
    ecc_concat2(
        expected_tag,
        envelope->nonce, Nn,
        cleartext_creds_buf, cleartext_creds_len
    );

    hmac(SHA512, expected_tag, Nn+cleartext_creds_len, auth_key, Nh, envelope->auth_tag);
    
    //If !ct_equal(envelope.auth_tag, expected_tag)
    if (cmp(envelope->auth_tag,expected_tag,Nn+cleartext_creds_len)){
      fprintf(stderr, "Error: auth_tag is not valid! \n");
      return -1;
    }

    return 1;
}


/**
  * REGISTRATION PART (PHASE 1)
  * ---------------------------
  * Registration part consists of 3 functions:
  *         - (request, blind) = CreateRegistrationRequest(password)
  *         - response = CreateRegistrationResponse(request, server_public_key, credential_identifier, oprf_seed)
  *         - (record, export_key) = FinalizeRegistrationRequest(response, server_identity, client_identity)
  *
  *
**/


/**
  *
  * Input:
  * @param[in]    ->  password    -> an opaque byte string containing the client's password.
  * @param[out]   ->  request     -> a RegistrationRequest structure.
  * @param[out]   ->  blind       -> an OPRF scalar value.
**/
void CreateRegistrationRequestWithBlind( 
    uint8_t blind[32], 
    RegistrationRequest *request, 
    uint8_t* password, int password_len
  ) {
 
  uint8_t blinded_message[32];
  
  //(blind, blinded_element) = Blind(password)
  //blinded_message = SerializeElement(blinded_element)
  // NOTE that ecc_voprf_ristretto255_sha512_BlindWithScalar returns serialized element already
  ecc_voprf_ristretto255_sha512_BlindWithScalar(blinded_message, password, password_len, blind);

  // RegistrationRequest();
  memcpy(request->blinded_message,blinded_message,32);

}



// CreateRegistrationResponse

// Input:
// - request, a RegistrationRequest structure.
// - server_public_key, the server's public key.
// - credential_identifier, an identifier that uniquely represents the credential.
// - oprf_seed, the seed of Nh bytes used by the server to generate an oprf_key.

// Output:
// - response, a RegistrationResponse structure.

// Exceptions:
// - DeserializeError, when OPRF element deserialization fails.
// - DeriveKeyPairError, when OPRF key derivation fails.

// def CreateRegistrationResponse(request, server_public_key,
//                                credential_identifier, oprf_seed):
//   seed = Expand(oprf_seed, concat(credential_identifier, "OprfKey"), Nok)
//   (oprf_key, _) = DeriveKeyPair(seed, "OPAQUE-DeriveKeyPair")

//   blinded_element = DeserializeElement(request.blinded_message)
//   evaluated_element = BlindEvaluate(oprf_key, blinded_element)
//   evaluated_message = SerializeElement(evaluated_element)

//   Create RegistrationResponse response with (evaluated_message, server_public_key)
//   return response


void CreateRegistrationResponse(
    RegistrationResponse *response,
    RegistrationRequest *request,
    uint8_t server_public_key[Npk],
    uint8_t *credential_identifier, int credential_identifier_len,
    uint8_t oprf_seed[Nh]
    ) {

    uint8_t seed_label[7] = {'O','p','r','f','K','e','y'};

    uint8_t seed_info[credential_identifier_len + 7];    

    //seed = Expand(oprf_seed, concat(credential_identifier, "OprfKey"), Nok)
    uint8_t seed[Nok];
    ecc_concat2(seed_info, credential_identifier, credential_identifier_len, seed_label, 7);
    hkdfExpand(SHA512,oprf_seed,Nh, seed_info, credential_identifier_len + 7, seed, Nok);


    // (oprf_key, _) = DeriveKeyPair(seed, "OPAQUE-DeriveKeyPair")
    uint8_t oprf_key[Nsk];
    uint8_t ignore[Npk];


    uint8_t info[20] = "OPAQUE-DeriveKeyPair";
    int infoLen = 20;
    DeterministicDeriveKeyPair(
        oprf_key,
        ignore,
        seed,
        info, infoLen
      ); 


//   blinded_element = DeserializeElement(request.blinded_message)
    // NOTE that DeserializeElement is not needed since blinded_message is already deserialized
//   evaluated_element = BlindEvaluate(oprf_key, blinded_element)
    BlindEvaluate(response->evaluated_message, oprf_key, request->blinded_message);
    //evaluated_message = SerializeElement(evaluated_element)
    // NOTE that serialization is not needed, it is already made it in BlindEvaluate
    memcpy(response->server_public_key, server_public_key, Npk);


    
}


// FinalizeRegistrationRequest

// Input:
// - password, an opaque byte string containing the client's password.
// - blind, an OPRF scalar value.
// - response, a RegistrationResponse structure.
// - server_identity, the optional encoded server identity.
// - client_identity, the optional encoded client identity.

// Output:
// - record, a RegistrationRecord structure.
// - export_key, an additional client key.

// Exceptions:
// - DeserializeError, when OPRF element deserialization fails.

// def FinalizeRegistrationRequest(password, blind, response, server_identity, client_identity):
//   evaluated_element = DeserializeElement(response.evaluated_message)
//   oprf_output = Finalize(password, blind, evaluated_element)

//   stretched_oprf_output = Stretch(oprf_output)
//   randomized_password = Extract("", concat(oprf_output, stretched_oprf_output))

//   (envelope, client_public_key, masking_key, export_key) =
//     Store(randomized_password, response.server_public_key,
//           server_identity, client_identity)
//   Create RegistrationRecord record with (client_public_key, masking_key, envelope)
//   return (record, export_key)


void FinalizeRegistrationRequest(
   RegistrationRecord *record,
   uint8_t export_key[Nh],
   uint8_t* password, int password_len,
   uint8_t blind[32],
   RegistrationResponse *response,
   uint8_t *server_identity, int server_identity_len,
   uint8_t *client_identity, int client_identity_len
  ) {

  uint8_t oprf_output[Nh];

  Finalize(
    oprf_output,
    password, password_len,
    blind, 
    response->evaluated_message
    );

  // STRETCHING .. msg = Stretch(msg) SO WE CAN SKIP THIS FOR NOW

  uint8_t password_info[Nh+Nh];
  ecc_concat2(password_info, oprf_output, Nh, oprf_output, Nh);
  uint8_t randomized_password[Nh];  
  hkdfExtract(SHA512,(uint8_t*) ' ',0, password_info, Nh+Nh, randomized_password);
  
  Store(
      &record->envelope,
      record->client_public_key,
      record->masking_key,
      export_key,
      randomized_password, Nh,
      response->server_public_key,
      server_identity, server_identity_len,
      client_identity, client_identity_len
    );


}


/**
  * Online Authenticated Key Exchange/ LOGIN
  *
  *    Client                                         Server
  * ------------------------------------------------------
  *  ke1 = GenerateKE1(password)
  *
  *                         ke1
  *              ------------------------->
  *
  *  ke2 = GenerateKE2(server_identity, server_private_key,
  *                    server_public_key, record,
  *                    credential_identifier, oprf_seed, ke1)
  *
  *                         ke2
  *              <-------------------------
  *
  *    (ke3,
  *    session_key,
  *    export_key) = GenerateKE3(client_identity,
  *                               server_identity, ke2)
  *
  *                         ke3
  *              ------------------------->
  *
  *                       session_key = ServerFinish(ke3)
**/






/**

CreateCredentialRequest

Input:
- password, an opaque byte string containing the client's password.

Output:
- request, a CredentialRequest structure.
- blind, an OPRF scalar value.

Exceptions:
- InvalidInputError, when Blind fails

def CreateCredentialRequest(password):
  (blind, blinded_element) = Blind(password)
  blinded_message = SerializeElement(blinded_element)
  Create CredentialRequest request with blinded_message
  return (request, blind)

**/



static void CreateCredentialRequest(
    uint8_t *password, int password_len,
    CredentialRequest *request,
    uint8_t blind[32]
  ) {

  ecc_voprf_ristretto255_sha512_BlindWithScalar(request->blinded_message, password, password_len, blind);

}

void ecc_opaque_ristretto255_sha512_DeriveDiffieHellmanKeyPair(
    uint8_t private_key[Nsk], uint8_t public_key[Npk],
    uint8_t seed[Nseed]
) {
    uint8_t info[33] = "OPAQUE-DeriveDiffieHellmanKeyPair";
    DeterministicDeriveKeyPair(
        private_key,
        public_key,
        seed,
        info, 33
    );
}


void ecc_opaque_ristretto255_sha512_3DH_StartWithSeed(
    KE1 *ke1,
    ClientState *state,
    CredentialRequest *credential_request,
    const uint8_t *client_nonce,
    const uint8_t *seed
) {
    // Steps:
    // 1. client_nonce = random(Nn)
    // 2. client_secret, client_keyshare = GenerateAuthKeyPair()
    // 3. Create KE1 ke1 with (credential_request, client_nonce, client_keyshare)
    // 4. state.client_secret = client_secret
    // 5. Output (ke1, client_secret)


    // 2. client_secret, client_keyshare = GenerateAuthKeyPair()
    uint8_t client_secret[Nsk];
    uint8_t client_keyshare[Npk];
    ecc_opaque_ristretto255_sha512_DeriveDiffieHellmanKeyPair(client_secret, client_keyshare, (uint8_t *)seed);


    // 3. Create KE1_t ke1 with (credential_request, client_nonce, client_keyshare)

    memcpy(ke1->credential_request.blinded_message, credential_request->blinded_message, Noe);
    memcpy(ke1->auth_request.client_nonce, client_nonce, 32);
    memcpy(ke1->auth_request.client_public_keyshare, client_keyshare, 32);

    // 4. state.client_secret = client_secret
    // 5. Output (ke1, client_secret)
    memcpy(state->client_ake_state.client_secret, client_secret, 32);
    // save KE1 in the client state
    memcpy(&state->client_ake_state.ke1, ke1, sizeof(KE1));
}



/**
  * GenerateKE1
  * 
  * State:
  * - state, a ClientState structure.
  * 
  * Input:
  * - password, an opaque byte string containing the client's password.
  * 
  * Output:
  * - ke1, a KE1 message structure.
  * 
  * def GenerateKE1(password):
  *   request, blind = CreateCredentialRequest(password)
  *   state.password = password
  *   state.blind = blind
  *   ke1 = AuthClientStart(request)
  *   return ke1
**/


void GenerateKE1(
  KE1 *ke1,
  ClientState *state,
  
  uint8_t *password, int password_len,
  uint8_t blind[32],
  uint8_t client_nonce[32],
  uint8_t seed[Nseed]) {

  CredentialRequest request;
  
  

  memcpy(state->password,password,password_len);
  // random blind
  CreateCredentialRequest(password,password_len,&request,blind);
  memcpy(state->blind,blind,32);

  printf("\nrequest....\n");
  print_32(request.blinded_message);
  state->password_len = password_len;
  //ke1 = AuthClientStart(request) -> 3DH-ristretto
  // random client nonce
  ecc_opaque_ristretto255_sha512_3DH_StartWithSeed(
        ke1, state, &request,
        client_nonce,
        seed
    );



}


/**
  * GenerateKE2
  * 
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


void ecc_opaque_ristretto255_sha512_CreateCredentialResponseWithMasking(
    CredentialResponse *response_raw,
    const CredentialRequest *request_raw,
    const uint8_t server_public_key[32],
    const RegistrationRecord *record_raw,
    const uint8_t *credential_identifier, const int credential_identifier_len,
    const uint8_t oprf_seed[Nh],
    const uint8_t masking_nonce[Nn]
) {
    // Steps:
    // 1. seed = Expand(oprf_seed, concat(credential_identifier, "OprfKey"), Nok)
    // 2. (oprf_key, _) = DeriveKeyPair(seed)
    // 3. Z = Evaluate(oprf_key, request.data, nil)
    // 4. masking_nonce = random(Nn)
    // 5. credential_response_pad = Expand(record.masking_key,
    //      concat(masking_nonce, "CredentialResponsePad"), Npk + Ne)
    // 6. masked_response = xor(credential_response_pad,
    //                          concat(server_public_key, record.envelope))
    // 7. Create CredentialResponse response with (Z, masking_nonce, masked_response)
    // 8. Output response


    // 1. seed = Expand(oprf_seed, concat(credential_identifier, "OprfKey"), Nok)
    // - concat(credential_identifier, "OprfKey")



//    const int seed_info_len = credential_identifier_len + 7;
//    uint8_t seed_info[256];
//    uint8_t oprf_key_label[7] = "OprfKey";
//    ecc_concat2(seed_info, credential_identifier, credential_identifier_len, oprf_key_label, 7);
//    // - Expand(oprf_seed, ikm_info, Nok)
//    uint8_t seed[Nok];
//
//    hkdfExpand(SHA512,oprf_seed,Nh,seed_info, seed_info_len, seed, Nok);
//
//    //ecc_kdf_hkdf_sha512_expand(seed, oprf_seed, seed_info, seed_info_len, Nok);
//
//    // 2. (oprf_key, _) = DeriveKeyPair(seed)
//    uint8_t oprf_key[32];
//    uint8_t ignore[32];
//    ecc_opaque_ristretto255_sha512_DeriveDiffieHellmanKeyPair(oprf_key, ignore, seed);

    
    uint8_t seed_label[7] = {'O','p','r','f','K','e','y'};

    uint8_t seed_info[credential_identifier_len + 7];    

    //seed = Expand(oprf_seed, concat(credential_identifier, "OprfKey"), Nok)
    uint8_t seed[Nok];
    ecc_concat2(seed_info, credential_identifier, credential_identifier_len, seed_label, 7);
    hkdfExpand(SHA512,oprf_seed,Nh, seed_info, credential_identifier_len + 7, seed, Nok);


    // (oprf_key, _) = DeriveKeyPair(seed, "OPAQUE-DeriveKeyPair")
    uint8_t oprf_key[Nsk];
    uint8_t ignore[Npk];


    uint8_t info[20] = "OPAQUE-DeriveKeyPair";
    int infoLen = 20;
    DeterministicDeriveKeyPair(
        oprf_key,
        ignore,
        seed,
        info, infoLen
      ); 


    // 3. Z = Evaluate(oprf_key, request.data, nil)
    uint8_t Z[32];
    BlindEvaluate(
        Z,
        oprf_key,
        (uint8_t *)request_raw->blinded_message
    );


    // 5. credential_response_pad = Expand(record.masking_key,
    //      concat(masking_nonce, "CredentialResponsePad"), Npk + Ne)
    uint8_t credential_response_pad_label[21] = "CredentialResponsePad";
    uint8_t credential_response_pad_info[Nn + 21];
    ecc_concat2(credential_response_pad_info, masking_nonce, Nn, credential_response_pad_label, 21);
    uint8_t credential_response_pad[Npk + Ne];
    
    hkdfExpand(SHA512,record_raw->masking_key,Nh, credential_response_pad_info,sizeof credential_response_pad_info , credential_response_pad, Npk + Ne);

    //ecc_kdf_hkdf_sha512_expand(credential_response_pad, record_raw->masking_key, credential_response_pad_info, sizeof credential_response_pad_info, Npk + Ne);

    // 6. masked_response = xor(credential_response_pad,
    //                          concat(server_public_key, record.envelope))
    uint8_t masked_response_xor[Npk + Ne];
    ecc_concat2(masked_response_xor, server_public_key, Npk, (const uint8_t *) &record_raw->envelope, Ne); // NOTE is it working????
    uint8_t masked_response[Npk + Ne];
    ecc_strxor(masked_response, credential_response_pad, masked_response_xor, Npk + Ne);

    // 7. Create CredentialResponse response with (Z, masking_nonce, masked_response)
    // 8. Output response
    memcpy(response_raw->evaluated_message, Z, sizeof Z);
    memcpy(response_raw->masking_nonce, masking_nonce, Nn);
    memcpy(response_raw->masked_response, masked_response, sizeof masked_response);

    // cleanup stack memory
    // ecc_memzero(seed_info, sizeof seed_info);
    // ecc_memzero(seed, sizeof seed);
    // ecc_memzero(oprf_key, sizeof oprf_key);
    // ecc_memzero(ignore, sizeof ignore);
    // ecc_memzero(Z, sizeof Z);
    // ecc_memzero(credential_response_pad_info, sizeof credential_response_pad_info);
    // ecc_memzero(credential_response_pad, sizeof credential_response_pad);
    // ecc_memzero(masked_response_xor, sizeof masked_response_xor);
    // ecc_memzero(masked_response, sizeof masked_response);
}


int ecc_opaque_ristretto255_sha512_3DH_Preamble(
    uint8_t *preamble,
    const int preamble_len,
    const uint8_t *context, const int context_len,
    const uint8_t *client_identity, const int client_identity_len,
    const uint8_t *client_public_key,
    const KE1 *ke1,
    const uint8_t *server_identity, const int server_identity_len,
    const uint8_t *server_public_key,
    const KE2 *ke2
) {
    // Steps:
    // 1. preamble = concat("OPAQUEv1-",
    //                      I2OSP(len(context), 2), context,
    //                      I2OSP(len(client_identity), 2), client_identity,
    //                      ke1,
    //                      I2OSP(len(server_identity), 2), server_identity,
    //                      inner_ke2)
    // 2. Output preamble


    uint8_t preamble_label[9] = "OPAQUEv1-";

    uint8_t *p = preamble;
    int n = preamble_len;
    n = 0;

    ecc_concat2(p + n, preamble_label, sizeof preamble_label, NULL, 0);
    n += sizeof preamble_label;
    ecc_I2OSP(p + n, context_len, 2);
    n += 2;
    ecc_concat2(p + n, context, context_len, NULL, 0);
    n += context_len;
    if (client_identity != NULL && client_identity_len > 0) {
        ecc_I2OSP(p + n, client_identity_len, 2);
        n += 2;
        ecc_concat2(p + n, client_identity, client_identity_len, NULL, 0);
        n += client_identity_len;
    } else {
        ecc_I2OSP(p + n, Npk, 2);
        n += 2;
        ecc_concat2(p + n, client_public_key, Npk, NULL, 0);
        n += Npk;
    }
    ecc_concat2(p + n, (uint8_t*)ke1, Ne, NULL, 0);
    n += Ne;
    if (server_identity != NULL && server_identity_len > 0) {
        ecc_I2OSP(p + n, server_identity_len, 2);
        n += 2;
        ecc_concat2(p + n, server_identity, server_identity_len, NULL, 0);
        n += server_identity_len;
    } else {
        ecc_I2OSP(p + n, Npk, 2);
        n += 2;
        ecc_concat2(p + n, server_public_key, Npk, NULL, 0);
        n += Npk;
    }
    ecc_concat2(p + n, (const uint8_t *) &(ke2->credential_response), Noe+Nn+Npk+Nn+Nm, NULL, 0);
    n += Noe+Nn+Npk+Nn+Nm;
    ecc_concat2(p + n, ke2->auth_response.server_nonce, Nn, NULL, 0);
    n += Nn;
    ecc_concat2(p + n, ke2->auth_response.server_public_keyshare, Npk, NULL, 0);
    n += Npk;


    return n;
}

void ecc_opaque_ristretto255_sha512_3DH_TripleDHIKM(
    uint8_t *ikm, // 96
    const uint8_t *sk1, const uint8_t *pk1,
    const uint8_t *sk2, const uint8_t *pk2,
    const uint8_t *sk3, const uint8_t *pk3
) {
    // Steps:
    // 1. dh1 = sk1 * pk1
    // 2. dh2 = sk2 * pk2
    // 3. dh3 = sk3 * pk3
    // 4. Output concat(dh1, dh2, dh3)

    uint8_t dh1[32];
    ScalarMult_(dh1, (uint8_t*) sk1, (uint8_t*)pk1);
    uint8_t dh2[32];
    ScalarMult_(dh2, (uint8_t*) sk2, (uint8_t*)pk2);
    uint8_t dh3[32];
    ScalarMult_(dh3, (uint8_t*) sk3, (uint8_t*)pk3);

    ecc_concat3(
        ikm,
        dh1, 32,
        dh2, 32,
        dh3, 32
    );

    // cleanup stack memory
    //ecc_memzero(dh1, sizeof dh1);
    //ecc_memzero(dh2, sizeof dh2);
    //ecc_memzero(dh3, sizeof dh3);
}


void ecc_opaque_ristretto255_sha512_3DH_Expand_Label(
    uint8_t *out, // 64
    const uint8_t *secret,
    const uint8_t *label, const int label_len,
    const uint8_t *context, const int context_len,
    const int length
) {
    // Expand-Label(Secret, Label, Context, Length) =
    //     Expand(Secret, CustomLabel, Length)
    //
    // struct {
    //   uint16 length = Length;
    //   opaque label<8..255> = "OPAQUE-" + Label;
    //   uint8 context<0..255> = Context;
    // } CustomLabel;

    uint8_t opaque_prefix[7] = "OPAQUE-";

    uint8_t info[512];
    uint8_t *p = &info[0];
    int n = 0;

    ecc_I2OSP(p + n, length, 2);
    n += 2;
    ecc_I2OSP(p + n, 7 + label_len, 1);
    n += 1;
    ecc_concat2(p + n, opaque_prefix, 7, label, label_len);
    n += 7 + label_len;
    ecc_I2OSP(p + n, context_len, 1);
    n += 1;
    ecc_concat2(p + n, context, context_len, NULL, 0);
    n += context_len;

    //ecc_kdf_hkdf_sha512_expand(out, secret, info, n, length);

    hkdfExpand(SHA512,secret,Nh,info, n, out, length);


    // cleanup stack memory
    //ecc_memzero(info, sizeof info);
}


void ecc_opaque_ristretto255_sha512_3DH_DeriveKeys(
    uint8_t *km2, // 64
    uint8_t *km3, // 64
    uint8_t *session_key, // 64
    const uint8_t *ikm, const int ikm_len,
    const uint8_t *preamble, const int preamble_len
) {
    // Steps:
    // 1. prk = Extract("", ikm)
    // 2. handshake_secret = Derive-Secret(prk, "HandshakeSecret", Hash(preamble))
    // 3. session_key = Derive-Secret(prk, "SessionKey", Hash(preamble))
    // 4. Km2 = Derive-Secret(handshake_secret, "ServerMAC", "")
    // 5. Km3 = Derive-Secret(handshake_secret, "ClientMAC", "")
    // 6. Output (Km2, Km3, session_key)

    // 1. prk = Extract("", ikm)
    uint8_t prk[64];
    //ecc_kdf_hkdf_sha512_extract(prk, NULL, 0, ikm, ikm_len);
    hkdfExtract(SHA512,(uint8_t*) NULL,0, ikm, ikm_len, prk);

    // 2. handshake_secret = Derive-Secret(prk, "HandshakeSecret", Hash(preamble))
    uint8_t preamble_secret_label[15] = "HandshakeSecret";
    uint8_t preamble_hash[64];

    SHA512Context mySha512;

    SHA512Reset(&mySha512);
    SHA512Input(&mySha512, preamble, preamble_len);
    SHA512Result(&mySha512, preamble_hash);

    //ecc_hash_sha512(preamble_hash, preamble, preamble_len);
    uint8_t handshake_secret[64];
    ecc_opaque_ristretto255_sha512_3DH_Expand_Label(
        handshake_secret,
        prk,
        preamble_secret_label, sizeof preamble_secret_label,
        preamble_hash, sizeof preamble_hash, Nx
    );

    // 3. session_key = Derive-Secret(prk, "SessionKey", Hash(preamble))
    uint8_t session_key_label[10] = "SessionKey";
    ecc_opaque_ristretto255_sha512_3DH_Expand_Label(
        session_key,
        prk,
        session_key_label, sizeof session_key_label,
        preamble_hash, sizeof preamble_hash, Nx
    );

    // 4. Km2 = Derive-Secret(handshake_secret, "ServerMAC", "")
    uint8_t km2_label[9] = "ServerMAC";
    ecc_opaque_ristretto255_sha512_3DH_Expand_Label(
        km2,
        handshake_secret,
        km2_label, sizeof km2_label,
        NULL, 0, Nx
    );

    // 5. Km3 = Derive-Secret(handshake_secret, "ClientMAC", "")
    uint8_t km3_label[9] = "ClientMAC";
    ecc_opaque_ristretto255_sha512_3DH_Expand_Label(
        km3,
        handshake_secret,
        km3_label, sizeof km3_label,
        NULL, 0, Nx
    );

    // cleanup stack memory
    //ecc_memzero(prk, sizeof prk);
    //ecc_memzero(preamble_hash, sizeof preamble_hash);
    //ecc_memzero(handshake_secret, sizeof handshake_secret);
}


void ecc_opaque_ristretto255_sha512_3DH_ResponseWithSeed(
    KE2 *ke2,
    ServerState *state,
    const uint8_t *server_identity, const int server_identity_len,
    const uint8_t server_private_key[32],
    const uint8_t server_public_key[32],
    const uint8_t *client_identity, const int client_identity_len,
    const uint8_t client_public_key[32],
    const KE1 *ke1,
    const CredentialResponse *credential_response_raw,
    const uint8_t *context, const int context_len,
    const uint8_t server_nonce[Nn],
    const uint8_t seed[Nseed]
) {
    // Steps:
    // 1. server_nonce = random(Nn)
    // 2. server_secret, server_keyshare = GenerateAuthKeyPair()
    // 3. Create inner_ke2 ike2 with (credential_response, server_nonce, server_keyshare)
    // 4. preamble = Preamble(client_identity, ke1, server_identity, ike2)
    // 5. ikm = TripleDHIKM(server_secret, ke1.client_keyshare, server_private_key, ke1.client_keyshare, server_secret, client_public_key)
    // 6. Km2, Km3, session_key = DeriveKeys(ikm, preamble)
    // 7. server_mac = MAC(Km2, Hash(preamble))
    // 8. expected_client_mac = MAC(Km3, Hash(concat(preamble, server_mac))
    // 9. Populate state with ServerState(expected_client_mac, session_key)
    // 10. Create KE2_t ke2 with (ike2, server_mac)
    // 11. Output ke2

    // 2. server_secret, server_keyshare = GenerateAuthKeyPair()
    uint8_t server_secret[32];
    uint8_t server_keyshare[32];
    ecc_opaque_ristretto255_sha512_DeriveDiffieHellmanKeyPair(server_secret, server_keyshare, (uint8_t *)seed);

    // 3. Create inner_ke2 ike2 with (credential_response, server_nonce, server_keyshare)
   
    memcpy(&ke2->credential_response, credential_response_raw, sizeof(CredentialResponse));
    memcpy(ke2->auth_response.server_nonce, server_nonce, 32);
    memcpy(ke2->auth_response.server_public_keyshare, server_keyshare, 32);

    // 4. preamble = Preamble(client_identity, ke1, server_identity, ike2)
    uint8_t preamble[512];
    const int preamble_len = ecc_opaque_ristretto255_sha512_3DH_Preamble(
        preamble,
        sizeof preamble,
        context, context_len,
        client_identity, client_identity_len,
        client_public_key,
        ke1,
        server_identity, server_identity_len,
        server_public_key,
        ke2
    );

    // 5. ikm = TripleDHIKM(server_secret, ke1.client_keyshare, server_private_key, ke1.client_keyshare, server_secret, client_public_key)
    uint8_t ikm[96];
    ecc_opaque_ristretto255_sha512_3DH_TripleDHIKM(
        ikm,
        server_secret, ke1->auth_request.client_public_keyshare,
        server_private_key, ke1->auth_request.client_public_keyshare,
        server_secret, client_public_key
    );

    // 6. Km2, Km3, session_key = DeriveKeys(ikm, preamble)
    uint8_t km2[64];
    uint8_t km3[64];
    uint8_t session_key[64];
    ecc_opaque_ristretto255_sha512_3DH_DeriveKeys(
        km2, km3,
        session_key,
        ikm, sizeof ikm,
        preamble, preamble_len
    );

    // 7. server_mac = MAC(Km2, Hash(preamble))
    uint8_t preamble_hash[64];
    //ecc_hash_sha512(preamble_hash, preamble, preamble_len);
    SHA512Context mySha512;
    SHA512Reset(&mySha512);
    SHA512Input(&mySha512, preamble, preamble_len);
    SHA512Result(&mySha512, preamble_hash);

    uint8_t server_mac[64];
    // ecc_mac_hmac_sha512(
    //     server_mac,
    //     preamble_hash, sizeof preamble_hash,
    //     km2,
    //     sizeof km2
    // );

    hmac(SHA512, preamble_hash, sizeof preamble_hash, km2, sizeof km2, server_mac);


    // 8. expected_client_mac = MAC(Km3, Hash(concat(preamble, server_mac))
    uint8_t expected_client_mac_input[64];
    SHA512Context hst;
    SHA512Reset(&hst);
    SHA512Input(&hst, preamble, (unsigned long long) preamble_len);
    SHA512Input(&hst, server_mac, sizeof server_mac);
    SHA512Result(&hst, expected_client_mac_input);
    uint8_t expected_client_mac[64];
    // ecc_mac_hmac_sha512(
    //     expected_client_mac,
    //     expected_client_mac_input, sizeof expected_client_mac_input,
    //     km3,
    //     sizeof km3
    // );

    hmac(SHA512, expected_client_mac_input, sizeof expected_client_mac_input, km3, sizeof km3, expected_client_mac);

    // 9. Populate state with ServerState(expected_client_mac, session_key)
    memcpy(state->expected_client_mac, expected_client_mac, sizeof expected_client_mac);
    memcpy(state->session_key, session_key, sizeof session_key);

    // 10. Create KE2_t ke2 with (ike2, server_mac)
    // 11. Output ke2
    memcpy(ke2->auth_response.server_mac, server_mac, sizeof server_mac);

    // cleanup stack memory
    // ecc_memzero(preamble, sizeof preamble);
    // ecc_memzero(ikm, sizeof ikm);
    // ecc_memzero(km2, sizeof km2);
    // ecc_memzero(km3, sizeof km3);
    // ecc_memzero(session_key, sizeof session_key);
    // ecc_memzero(preamble_hash, sizeof preamble_hash);
    // ecc_memzero(server_mac, sizeof server_mac);
    // ecc_memzero(expected_client_mac_input, sizeof expected_client_mac_input);
    // ecc_memzero(expected_client_mac, sizeof expected_client_mac);
    // ecc_memzero((uint8_t *) &hst, sizeof hst);
}


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
) {
    // Steps:
    // 1. response = CreateCredentialResponse(ke1.request, server_public_key, record,
    //     credential_identifier, oprf_seed)
    // 2. ke2 = Response(server_identity, server_private_key,
    //     client_identity, record.client_public_key, ke1, response)
    // 3. Output ke2

    CredentialResponse response;
    ecc_opaque_ristretto255_sha512_CreateCredentialResponseWithMasking(
        &response,
        &ke1_raw->credential_request,
        server_public_key,
        record_raw,
        credential_identifier, credential_identifier_len,
        oprf_seed,
        masking_nonce
    );

    printf("\n skuska response:\n");
    print_32(response.evaluated_message);
    printf("\n ---\n");

    ecc_opaque_ristretto255_sha512_3DH_ResponseWithSeed(
        ke2_raw,
        state_raw,
        server_identity, server_identity_len,
        server_private_key,
        server_public_key,
        client_identity, client_identity_len,
        record_raw->client_public_key,
        ke1_raw,
        &response,
        context, context_len,
        server_nonce,
        seed
    );
}



int ecc_opaque_ristretto255_sha512_RecoverCredentials(
    uint8_t client_private_key[32],
    uint8_t server_public_key[32],
    uint8_t export_key[64], // 64
    const uint8_t *password, const int password_len,
    const uint8_t blind[Nok],
    const CredentialResponse *res,
    const uint8_t *server_identity, const int server_identity_len,
    const uint8_t *client_identity, const int client_identity_len
) {
    // Steps:
    // 1. y = Finalize(password, blind, response.data)
    // 2. randomized_pwd = Extract("", Harden(y, params))
    // 3. masking_key = Expand(randomized_pwd, "MaskingKey", Nh)
    // 4. credential_response_pad = Expand(masking_key,
    //      concat(response.masking_nonce, "CredentialResponsePad"), Npk + Ne)
    // 5. concat(server_public_key, envelope) = xor(credential_response_pad,
    //                                               response.masked_response)
    // 6. (client_private_key, export_key) =
    //     RecoverEnvelope(randomized_pwd, server_public_key, envelope,
    //                     server_identity, client_identity)
    // 7. Output (client_private_key, response.server_public_key, export_key)

    // 1. y = Finalize(password, blind, response.data)
    uint8_t y[64];
    Finalize(
        y,
        (uint8_t *) password, password_len,
        (uint8_t *) blind,
        (uint8_t *) res->evaluated_message
    );


    // 2. randomized_pwd = Extract("", Harden(y, params))
    // - Harden(y, params)
    uint8_t harden_result[Nh];
    memcpy(harden_result, y, Nh);
    
    // - concat(y, Harden(y, params))
    uint8_t extract_input[2 * Nh];
    ecc_concat2(extract_input, y, Nh, harden_result, Nh);
    uint8_t randomized_pwd[Nh];
    //ecc_kdf_hkdf_sha512_extract(randomized_pwd, NULL, 0, extract_input, sizeof extract_input);
    hkdfExtract(SHA512,(uint8_t*) NULL,0, extract_input, sizeof extract_input, randomized_pwd);

  
    // 3. masking_key = Expand(randomized_pwd, "MaskingKey", Nh)
    uint8_t masking_key_info[10] = "MaskingKey";
    uint8_t masking_key[Nh];
    //ecc_kdf_hkdf_sha512_expand(masking_key, randomized_pwd, masking_key_info, sizeof masking_key_info, Nh);
    hkdfExpand(SHA512,randomized_pwd,Nh,masking_key_info, sizeof masking_key_info, masking_key, Nh);

    // 4. credential_response_pad = Expand(masking_key,
    //      concat(response.masking_nonce, "CredentialResponsePad"), Npk + Ne)
    uint8_t credential_response_pad_label[21] = "CredentialResponsePad";
    uint8_t credential_response_pad_info[Nn + 21];
    ecc_concat2(credential_response_pad_info, res->masking_nonce, Nn, credential_response_pad_label, 21);
    uint8_t credential_response_pad[Npk + Ne];
    //ecc_kdf_hkdf_sha512_expand(credential_response_pad, masking_key, credential_response_pad_info, sizeof credential_response_pad_info, Npk + Ne);
    hkdfExpand(SHA512,masking_key,Nh,credential_response_pad_info, sizeof credential_response_pad_info, credential_response_pad, Npk + Ne);


    // 5. concat(server_public_key, envelope) = xor(credential_response_pad,
    //                                               response.masked_response)
    uint8_t xor_result[Npk + Ne];
    ecc_strxor(xor_result, credential_response_pad, res->masked_response, Npk + Ne);
    memcpy(server_public_key, xor_result, Npk);
    Envelope envelope;
    memcpy(envelope.nonce, &xor_result[Npk], Nn);
    memcpy(envelope.auth_tag, &xor_result[Npk+Nn], Nm);

    // 6. (client_private_key, export_key) =
    //     RecoverEnvelope(randomized_pwd, server_public_key, envelope,
    //                     server_identity, client_identity)
    
    CleartextCredentials ignore;
    const int ret = Recover(
        client_private_key,
        &ignore,
        export_key,
        randomized_pwd, Nh, // asi???
        server_public_key,
        &envelope,
        (uint8_t *)server_identity, server_identity_len,
        (uint8_t *)client_identity, client_identity_len
    );

    // cleanup stack memory
    // ecc_memzero(y, sizeof y);
    // ecc_memzero(randomized_pwd, sizeof randomized_pwd);
    // ecc_memzero(masking_key, sizeof masking_key);
    // ecc_memzero(credential_response_pad_info, sizeof credential_response_pad_info);
    // ecc_memzero(credential_response_pad, sizeof credential_response_pad);
    // ecc_memzero(xor_result, sizeof xor_result);
    // ecc_memzero(envelope, sizeof envelope);

    // 7. Output (client_private_key, response.server_public_key, export_key)
    return ret;
}




int ecc_opaque_ristretto255_sha512_3DH_ClientFinalize(
    KE3 *ke3_raw, // 64
    uint8_t session_key[64],
    ClientState *state,
    const uint8_t *client_identity, const int client_identity_len,
    const uint8_t client_private_key[32],
    const uint8_t *server_identity, const int server_identity_len,
    const uint8_t server_public_key[32],
    const KE2 *ke2,
    const uint8_t *context, const int context_len
) {
    // Steps:
    // 1. ikm = TripleDHIKM(state.client_secret, ke2.server_keyshare,
    //     state.client_secret, server_public_key, client_private_key, ke2.server_keyshare)
    // 2. preamble = Preamble(client_identity, state.ke1, server_identity, ke2.inner_ke2)
    // 3. Km2, Km3, session_key = DeriveKeys(ikm, preamble)
    // 4. expected_server_mac = MAC(Km2, Hash(preamble))
    // 5. If !ct_equal(ke2.server_mac, expected_server_mac),
    //      raise HandshakeError
    // 6. client_mac = MAC(Km3, Hash(concat(preamble, expected_server_mac))
    // 7. Create KE3 ke3 with client_mac
    // 8. Output (ke3, session_key)

    // 1. ikm = TripleDHIKM(state.client_secret, ke2.server_keyshare,
    //     state.client_secret, server_public_key, client_private_key, ke2.server_keyshare)
    uint8_t ikm[96];
    ecc_opaque_ristretto255_sha512_3DH_TripleDHIKM(
        ikm,
        state->client_ake_state.client_secret, ke2->auth_response.server_public_keyshare,
        state->client_ake_state.client_secret, server_public_key,
        client_private_key, ke2->auth_response.server_public_keyshare
    );

    uint8_t client_public_key[Npk];
    ScalarMult_(client_public_key, (uint8_t*)client_private_key,(uint8_t*)RISTRETTO255_BASEPOINT_OPRF);

    // 2. preamble = Preamble(client_identity, state.ke1, server_identity, ke2.inner_ke2)
    uint8_t preamble[512];
    const int preamble_len = ecc_opaque_ristretto255_sha512_3DH_Preamble(
        preamble,
        sizeof preamble,
        context, context_len,
        client_identity, client_identity_len,
        client_public_key,
        &state->client_ake_state.ke1,
        server_identity, server_identity_len,
        server_public_key,
        ke2
    );

    // 3. Km2, Km3, session_key = DeriveKeys(ikm, preamble)
    uint8_t km2[64];
    uint8_t km3[64];
    ecc_opaque_ristretto255_sha512_3DH_DeriveKeys(
        km2, km3,
        session_key,
        ikm, sizeof ikm,
        preamble, preamble_len
    );

    // 4. expected_server_mac = MAC(Km2, Hash(preamble))
    uint8_t preamble_hash[64];
    //ecc_hash_sha512(preamble_hash, preamble, preamble_len);

    SHA512Context mySha512;
    SHA512Reset(&mySha512);
    SHA512Input(&mySha512, preamble, preamble_len);
    SHA512Result(&mySha512, preamble_hash);

    uint8_t expected_server_mac[64];
    hmac(SHA512,
        preamble_hash, sizeof preamble_hash,
        km2,
        sizeof km2,
        expected_server_mac
    );

    // 5. If !ct_equal(ke2.server_mac, expected_server_mac),
    //      raise HandshakeError
    if (!cmp(ke2->auth_response.server_mac, expected_server_mac, Nh)) {
        // cleanup stack memory
        // ecc_memzero(ikm, sizeof ikm);
        // ecc_memzero(preamble, sizeof preamble);
        // ecc_memzero(km2, sizeof km2);
        // ecc_memzero(km3, sizeof km3);
        // ecc_memzero(preamble_hash, sizeof preamble_hash);
        // ecc_memzero(expected_server_mac, sizeof expected_server_mac);
        return -1;
    }

    // 6. client_mac = MAC(Km3, Hash(concat(preamble, expected_server_mac))
    uint8_t client_mac_input[64];
    SHA512Context hst;
    SHA512Reset(&hst);
    SHA512Input(&hst, preamble, preamble_len);
    SHA512Input(&hst, expected_server_mac, sizeof expected_server_mac);
    SHA512Result(&hst, client_mac_input);

    uint8_t client_mac[64];
    hmac(SHA512,
        client_mac_input, sizeof client_mac_input,
        km3,
        sizeof km3,
        client_mac
    );

    // 7. Create KE3 ke3 with client_mac
    // 8. Output (ke3, session_key)
    memcpy(ke3_raw->client_mac, client_mac, sizeof client_mac);

    // cleanup stack memory
    // ecc_memzero(ikm, sizeof ikm);
    // ecc_memzero(preamble, sizeof preamble);
    // ecc_memzero(km2, sizeof km2);
    // ecc_memzero(km3, sizeof km3);
    // ecc_memzero(preamble_hash, sizeof preamble_hash);
    // ecc_memzero(expected_server_mac, sizeof expected_server_mac);
    // ecc_memzero(client_mac_input, sizeof client_mac_input);
    // ecc_memzero(client_mac, sizeof client_mac);
    // ecc_memzero((byte_t *) &hst, sizeof hst);

    return 0;
}




// GENERATE KE3


int ecc_opaque_ristretto255_sha512_GenerateKE3(
    KE3 *ke3_raw,
    uint8_t session_key[64], // client_session_key
    uint8_t export_key[64], // 64
    ClientState *state,
    const uint8_t *client_identity, const int client_identity_len,
    const uint8_t *server_identity, const int server_identity_len,
    const KE2 *ke2,
    const uint8_t *context, const int context_len
) {
    // Steps:
    // 1. (client_private_key, server_public_key, export_key) =
    //     RecoverCredentials(password, state.blind, ke2.CredentialResponse,
    //                        server_identity, client_identity)
    // 2. (ke3, session_key) =
    //     ClientFinalize(client_identity, client_private_key, server_identity,
    //                     server_public_key, ke1, ke2)
    // 3. Output (ke3, session_key)

    // 1. (client_private_key, server_public_key, export_key) =
    //     RecoverCredentials(password, state.blind, ke2.CredentialResponse,
    //                        server_identity, client_identity)
    uint8_t client_private_key[32];
    uint8_t server_public_key[32];
    const int recover_ret = ecc_opaque_ristretto255_sha512_RecoverCredentials(
        client_private_key,
        server_public_key,
        export_key,
        state->password, state->password_len,
        state->blind,
        &ke2->credential_response,
        server_identity, server_identity_len,
        client_identity, client_identity_len
    );


    // 2. (ke3, session_key) =
    //     ClientFinalize(client_identity, client_private_key, server_identity,
    //                     server_public_key, ke1, ke2)
    const int finalize_ret = ecc_opaque_ristretto255_sha512_3DH_ClientFinalize(
        ke3_raw,
        session_key,
        state,
        client_identity, client_identity_len,
        client_private_key,
        server_identity, server_identity_len,
        server_public_key,
        ke2,
        context, context_len
    );


    // cleanup stack memory
    //ecc_memzero(client_private_key, sizeof client_private_key);
    //ecc_memzero(server_public_key, sizeof server_public_key);
//
    // 3. Output (ke3, session_key)
    if (recover_ret == 0 && finalize_ret == 0)
        return 0;
    else
        return -1;
}


int ecc_opaque_ristretto255_sha512_ServerFinish(
    uint8_t session_key[Nx],
    ServerState *state,
    const KE3 *ke3
) {
    // Steps:
    // 1. if !ct_equal(ke3.client_mac, state.expected_client_mac):
    // 2.    raise HandshakeError
    // 3. Output state.session_key

    if (!cmp(ke3->client_mac, state->expected_client_mac, Nh))
        return -1;

    memcpy(session_key, state->session_key, 64);

    return 0;
}