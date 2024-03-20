// ******************************************************************
// ----------------- TECHNICAL UNIVERSITY OF KOSICE -----------------
// ---Department of Electronics and Multimedia Telecommunications ---
// -------- FACULTY OF ELECTRICAL ENGINEERING AND INFORMATICS -------
// ------------ THIS CODE IS A PART OF A MASTER'S THESIS ------------
// ------------------------- Master thesis --------------------------
// -----------------Patrik Zelenak & Milos Drutarovsky --------------
// ------------------------version M.C.U 1.1.0 ----------------------
// --------------------------- 09-03-2024 ---------------------------
// ******************************************************************

// P.Z. A lot of features was removed to use just whats
// needed for MCU tests. Server-side functions are removed
// from the MCU version of OPAQUE because we believe that 
// clients, being potentially low-performance devices, 
// need optimization. In contrast, servers are typically 
// more powerful, and they can run the default OPAQUE version from:
// https://github.com/Alg0ritmus/OPAQUE-C


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
#include "dependencies/sha.h"
#include "ristretto255/ristretto255.h"
#include "ristretto255/helpers.h"
#include "ristretto255/utils.h"
#include "ristretto255/modl.h"
#include "ristretto255/prng.h"
#include "oprf.h"

#define TESTING_ENVELOPE_NONCE

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
static void CreateCleartextCredentials(
    CleartextCredentials *cleartext_credentials,
    const uint8_t server_public_key[Npk],
    const uint8_t client_public_key[Npk],
    const uint8_t server_identity[IDENTITY_BYTE_SIZE], uint32_t server_identity_len,
    const uint8_t client_identity[IDENTITY_BYTE_SIZE], uint32_t client_identity_len
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
// STACKSIZE: 8B
static uint32_t serializeCleartextCredentials(uint8_t *out, CleartextCredentials *credentials) {
    const uint32_t len = Npk + 2 + credentials->server_identity_len + 2 + credentials->client_identity_len;

    uint32_t offset = 0;
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
  * @param[in]   -> randomized_password -> random pass of 512 bytes in length
  * @param[in]   -> server_public_key   -> the encoded server public key for the AKE protocol
  * @param[in]   -> server_identity     -> the optional encoded server identity
  * @param[in]   -> client_identity     -> the optional encoded client identity
  * @param[out]  -> envelope            -> the client's Envelope structure
  * @param[out]  -> client_public_key   -> the client's AKE public key
  * @param[out]  -> masking_key         -> an encryption key used by the server with the sole purpose of defending against client enumeration attacks
  * @param[out]  -> export_key          -> an additional client key
**/

// https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-12.html
// STACKSIZE BEFORE CLEANING: 3030B // we can set as global variable ?
// STACKSIZE AFTER CLEANING: 2112B
void Store(
    Envelope *envelope, 
    uint8_t client_public_key[Npk],
    uint8_t masking_key[Nh],
    uint8_t export_key[Nh],
    const uint8_t *randomized_password, const uint32_t randomized_password_len,
    const uint8_t server_public_key[Npk],
    const uint8_t *server_identity, const uint32_t server_identity_len,
    const uint8_t *client_identity, const uint32_t client_identity_len
    ) {


    #ifdef TESTING_ENVELOPE_NONCE
        uint8_t envelope_nonce[Nn] = {0xac, 0x13, 0x17, 0x1b, 0x2f, 0x17, 0xbc, 0x2c, 0x74, 0x99, 0x7f, 0x0f, 0xce, 0x1e, 0x1f, 0x35, 0xbe, 0xc6, 0xb9, 0x1f, 0xe2, 0xe1, 0x2d, 0xbd, 0x32, 0x3d, 0x23, 0xba, 0x7a, 0x38, 0xdf, 0xec};
    #else
        uint8_t envelope_nonce[Nn];
        rand_32_bytes(envelope_nonce);
    #endif

 
    // NOTE: that Expand/Extract should be taken from HKDF 
    // https://tools.ietf.org/html/rfc5869

    uint8_t masking_key_info[10] = {'M', 'a', 's', 'k', 'i', 'n', 'g', 'K', 'e', 'y'};
    uint8_t auth_key_label[7] = {'A', 'u', 't', 'h', 'K', 'e', 'y'};
    uint8_t export_key_label[9] = {'E', 'x', 'p', 'o', 'r', 't', 'K', 'e', 'y'};
    uint8_t seed_label[10] = {'P', 'r', 'i', 'v', 'a', 't', 'e', 'K', 'e', 'y'};

    hkdfExpand(randomized_password,randomized_password_len, masking_key_info, 10, masking_key, Nh);

    // temp_buffer is set to 296 bytes, this variable is used to reduce amount of allocated bytes 
    // needed for expanding export key, masking key, seed and cleartext_creds_buf later

    uint8_t temp_buffer[296];
    
    
    // uint8_t export_key_info[Nn+9]; NOTE that in this point, overhead is 255 bytes (296-(32+9))
    // meaning, that we allocated more than we acctually needed by 255 bytes
    // after expanding export_key, we no longer need to store this information
    #define export_key_info temp_buffer
    ecc_concat2(export_key_info, envelope_nonce, Nn, export_key_label, 9);
    hkdfExpand(randomized_password,randomized_password_len, export_key_info, Nn+9, export_key, Nh);

    
    // instead of new seed variable we will rewrite 32 lower bytes of temp_buffer
    // to save some space on stack same will apply on seed_info on upper 42 bytes.

    //uint8_t seed[Nseed];
    #define seed temp_buffer //lower 32 bytes of temp_buffer is allocated for seed

    // uint8_t seed_info[Nn + 10];
    #define seed_info &temp_buffer[32] //next 42 bytes of temp_buffer is allocated for seed_info
    

    ecc_concat2(seed_info, envelope_nonce, Nn, seed_label, 10);
    hkdfExpand(randomized_password,randomized_password_len, seed_info, Nn+10, seed, Nseed);
    
    //uint8_t skS[Nsk]; // dont need this bcs we are acctually using temp_buffer

    #define skS &temp_buffer[32] // saving space on stack, bcs we dont need space previously allocated for seed_info
    uint8_t info[33] = {'O', 'P', 'A', 'Q', 'U', 'E', '-', 'D', 'e', 'r', 'i', 'v', 'e', 'D', 'i', 'f', 'f', 'i', 'e', 'H', 'e', 'l', 'l', 'm', 'a', 'n', 'K', 'e', 'y', 'P', 'a', 'i', 'r'};
    //DeriveDiffieHellmanKeyPair(seed);

    // do not forget to clear skS from stack
    DeterministicDeriveKeyPair(skS,client_public_key,seed, info, 33);
    


    // During memory optimization we reduced  size of CleartextCredentials to STACKSIZE: 296B
    CleartextCredentials clear_cred; 
    CleartextCredentials *cleartext_credentials = &clear_cred;

    CreateCleartextCredentials(
        cleartext_credentials, 
        server_public_key, 
        client_public_key,
        server_identity, server_identity_len, 
        client_identity, client_identity_len
      );


    //uint8_t cleartext_creds_buf[296];
    #define cleartext_creds_buf temp_buffer // saving space on stack

    uint32_t cleartext_creds_len = serializeCleartextCredentials(
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


    //uint8_t auth_key[Nh];
    #define auth_key temp_buffer // saving space on stack (lower 64 bytes are auth_key)
    
    //uint8_t auth_key_info[Nn + 7];
    #define auth_key_info &temp_buffer[Nh] // saving space on stack (next 39 bytes are auth_key_info)
    
    ecc_concat2(auth_key_info, envelope_nonce, Nn, auth_key_label, 7);
    hkdfExpand(randomized_password,randomized_password_len, auth_key_info, Nn+7, auth_key, Nh);

    hmac(auth_tag_mac_input, Nn+cleartext_creds_len, auth_key, Nh, envelope->auth_tag);
    memcpy(envelope->nonce, envelope_nonce, Nn);

    //crypto_wipe(auth_key, sizeof auth_key); 
    //crypto_wipe(auth_key_info, sizeof auth_key_info); 
    //crypto_wipe(export_key_info, sizeof export_key_info);
    //crypto_wipe(seed, sizeof seed);
    //crypto_wipe(seed_info, sizeof seed_info);
    //crypto_wipe(skS, sizeof skS);
    crypto_wipe(temp_buffer, 296);
    crypto_wipe(cleartext_credentials, sizeof cleartext_credentials); 
    crypto_wipe(auth_tag_mac_input, sizeof auth_tag_mac_input);
    #undef export_key_info 
    #undef seed
    #undef seed_info
    #undef skS
    #undef cleartext_creds_buf
    #undef auth_key
    #undef auth_key_info
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

// STACKSIZE BEFORE CLEANING: 2500B
// STACKSIZE AFTER CLEANING: 2075B
static uint32_t Recover(
    uint8_t client_private_key[Npk],
    CleartextCredentials *cleartext_credentials,
    uint8_t export_key[Nh],

    const uint8_t *randomized_password, const uint32_t randomized_password_len,
    const uint8_t server_public_key[Npk],
    const Envelope *envelope, 
    const uint8_t *server_identity, const uint32_t server_identity_len,
    const uint8_t *client_identity, const uint32_t client_identity_len
  ) {
  
    uint8_t auth_key_label[7] = {'A', 'u', 't', 'h', 'K', 'e', 'y'};
    uint8_t export_key_label[9] = {'E', 'x', 'p', 'o', 'r', 't', 'K', 'e', 'y'};
    uint8_t seed_label[10] = {'P', 'r', 'i', 'v', 'a', 't', 'e', 'K', 'e', 'y'};

    // temp_buffer is set to 296 bytes, this variable is used to reduce amount of allocated bytes 
    // needed for expanding export key, etc. like we did in Store() above

    uint8_t temp_buffer[296];

    //uint8_t export_key_info[Nn+9];
    #define export_key_info temp_buffer // save space on stack
    
    //uint8_t seed[Nseed];
    #define seed temp_buffer //lower 32 bytes of temp_buffer is allocated for seed

    //uint8_t seed_info[Nn + 10];
    #define seed_info &temp_buffer[32] //next 42 bytes of temp_buffer is allocated for seed_info
    


    //export_key = Expand(randomized_password, concat(envelope.nonce, "ExportKey"), Nh)
    ecc_concat2(export_key_info, envelope->nonce, Nn, export_key_label, 9);
    hkdfExpand(randomized_password,randomized_password_len, export_key_info, Nn+9, export_key, Nh);

    //seed = Expand(randomized_password, concat(envelope.nonce, "PrivateKey"), Nseed)
    ecc_concat2(seed_info, envelope->nonce, Nn, seed_label, 10);
    hkdfExpand(randomized_password,randomized_password_len, seed_info, Nn+10, seed, Nseed);

    //(client_private_key, client_public_key) = DeriveDiffieHellmanKeyPair(seed)
    //uint8_t client_public_key[Npk]; //save space on stack
    #define client_public_key &temp_buffer[32]
    uint8_t info[33] = {'O', 'P', 'A', 'Q', 'U', 'E', '-', 'D', 'e', 'r', 'i', 'v', 'e', 'D', 'i', 'f', 'f', 'i', 'e', 'H', 'e', 'l', 'l', 'm', 'a', 'n', 'K', 'e', 'y', 'P', 'a', 'i', 'r'};
    uint32_t infoLen = 33;
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
    // uint8_t cleartext_creds_buf[296];

    #define cleartext_creds_buf temp_buffer // saving space on stack

    uint32_t cleartext_creds_len = serializeCleartextCredentials(
        cleartext_creds_buf,
        cleartext_credentials
    );

    uint8_t expected_tag[Nn+cleartext_creds_len];
    ecc_concat2(
        expected_tag,
        envelope->nonce, Nn,
        cleartext_creds_buf, cleartext_creds_len
    );

    //auth_key = Expand(randomized_password, concat(envelope.nonce, "AuthKey"), Nh)

    //uint8_t auth_key[Nh];
    #define auth_key temp_buffer // saving space on stack (lower 64 bytes are auth_key)
    
    //uint8_t auth_key_info[Nn + 7];
    #define auth_key_info &temp_buffer[Nh] // saving space on stack (next 39 bytes are auth_key_info)
    
    ecc_concat2(auth_key_info, envelope->nonce, Nn, auth_key_label, 7);
    hkdfExpand(randomized_password,randomized_password_len, auth_key_info, Nn+7, auth_key, Nh);

    hmac(expected_tag, Nn+cleartext_creds_len, auth_key, Nh,  expected_tag);

    crypto_wipe(auth_key, sizeof auth_key);
    crypto_wipe(auth_key_info, sizeof auth_key_info);
    crypto_wipe(export_key_info, sizeof export_key_info);
    crypto_wipe(seed, sizeof seed);
    crypto_wipe(seed_info, sizeof seed_info);  
    crypto_wipe(client_public_key, sizeof client_public_key);
    crypto_wipe(cleartext_creds_buf, sizeof cleartext_creds_buf); 
    #undef export_key_info 
    #undef seed
    #undef seed_info
    #undef cleartext_creds_buf
    #undef auth_key
    #undef auth_key_info
    #undef client_public_key
    
    //If !ct_equal(envelope.auth_tag, expected_tag)
    if (!cmp(envelope->auth_tag,expected_tag,Nh)){
      printf("Error: auth_tag is not valid! \n");
      crypto_wipe(expected_tag, sizeof expected_tag); 
      return OPAQUE_ERROR;
    }
    crypto_wipe(expected_tag, sizeof expected_tag); 
    return OPAQUE_OK;
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
  * STACKSIZE: 1212B
**/
void CreateRegistrationRequestWithBlind( 
    const uint8_t blind[32], 
    RegistrationRequest *request, 
    const uint8_t* password, const uint32_t password_len
  ) {
 
  uint8_t blinded_message[32];
  
  //(blind, blinded_element) = Blind(password)
  //blinded_message = SerializeElement(blinded_element)
  // NOTE that ecc_voprf_ristretto255_sha512_BlindWithScalar returns serialized element already
  ecc_voprf_ristretto255_sha512_BlindWithScalar(blinded_message, password, password_len, blind);

  // RegistrationRequest();
  memcpy(request->blinded_message,blinded_message,32);

  crypto_wipe(blinded_message, sizeof blinded_message);

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
// STACKSIZE: ~1270B
void FinalizeRegistrationRequest(
   RegistrationRecord *record,
   uint8_t export_key[Nh],
   const uint8_t* password, const uint32_t password_len,
   const uint8_t blind[32],
   const RegistrationResponse *response,
   const uint8_t *server_identity, const uint32_t server_identity_len,
   const uint8_t *client_identity, const uint32_t client_identity_len
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
  hkdfExtract((uint8_t*) ' ',0, password_info, Nh+Nh, randomized_password);
  
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

  crypto_wipe(oprf_output, sizeof oprf_output); 
  crypto_wipe(password_info, sizeof password_info);
  crypto_wipe(randomized_password, sizeof randomized_password);

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


// STACKSIZE: 1501B
static void CreateCredentialRequest(
    uint8_t *password, uint32_t password_len,
    CredentialRequest *request,
    uint8_t blind[32]
  ) {

  ecc_voprf_ristretto255_sha512_BlindWithScalar(request->blinded_message, password, password_len, blind);

}


//STACKSIZE: 1697B
void ecc_opaque_ristretto255_sha512_DeriveDiffieHellmanKeyPair(
    uint8_t private_key[Nsk], uint8_t public_key[Npk],
    uint8_t seed[Nseed]
) {
    uint8_t info[33] = {'O', 'P', 'A', 'Q', 'U', 'E', '-', 'D', 'e', 'r', 'i', 'v', 'e', 'D', 'i', 'f', 'f', 'i', 'e', 'H', 'e', 'l', 'l', 'm', 'a', 'n', 'K', 'e', 'y', 'P', 'a', 'i', 'r'};
    DeterministicDeriveKeyPair(
        private_key,
        public_key,
        seed,
        info, 33
    );
}



//STACKSIZE: 1761B
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
    crypto_wipe(client_secret, sizeof client_secret);
    crypto_wipe(client_keyshare, sizeof client_keyshare);
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


// STACKSIZE: 1793B
void GenerateKE1(
  KE1 *ke1,
  ClientState *state,
  
  const uint8_t *password, const uint32_t password_len,
  const uint8_t blind[32],
  const uint8_t client_nonce[32],
  const uint8_t seed[Nseed]) {

  CredentialRequest request;
  
  

  memcpy(state->password,password,password_len);
  // random blind
  CreateCredentialRequest((uint8_t*) password,password_len,&request, (uint8_t*) blind);
  memcpy(state->blind,blind,32);

  //printf("\nrequest....\n");
  //print_32(request.blinded_message);
  state->password_len = password_len;
  //ke1 = AuthClientStart(request) -> 3DH-ristretto
  // random client nonce
  ecc_opaque_ristretto255_sha512_3DH_StartWithSeed(
        ke1, state, &request,
        client_nonce,
        seed
  );
 

  crypto_wipe(&request, sizeof(CredentialRequest));

}


// STACKSIZE: ~13B 
uint32_t ecc_opaque_ristretto255_sha512_3DH_Preamble(
    uint8_t *preamble,
    const uint32_t preamble_len,
    const uint8_t *context, const uint32_t context_len,
    const uint8_t *client_identity, const uint32_t client_identity_len,
    const uint8_t *client_public_key,
    const KE1 *ke1,
    const uint8_t *server_identity, const uint32_t server_identity_len,
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


    uint8_t preamble_label[9] = {'O', 'P', 'A', 'Q', 'U', 'E', 'v', '1', '-'};

    uint8_t *p = preamble;
    uint32_t n = preamble_len;
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

// STACKSIZE: 776B
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
    crypto_wipe(dh1, sizeof dh1);
    crypto_wipe(dh2, sizeof dh2);
    crypto_wipe(dh3, sizeof dh3);
}



// STACKSIZE BEFORE CLEANING: 1141B
void ecc_opaque_ristretto255_sha512_3DH_Expand_Label(
    uint8_t *out, // 64
    const uint8_t *secret,
    const uint8_t *label, const uint32_t label_len,
    const uint8_t *context, const uint32_t context_len,
    const uint32_t length
) {
    uint8_t opaque_prefix[7] = {'O', 'P', 'A', 'Q', 'U', 'E', '-'};

    uint8_t info[100];
    uint8_t *p = &info[0];
    uint32_t n = 0;

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

    hkdfExpand(secret,Nh,info, n, out, length);


    //cleanup stack memory
    crypto_wipe(info, sizeof info);
}


// STACKSIZE BEFORE CLEANING: 1657B
void ecc_opaque_ristretto255_sha512_3DH_DeriveKeys(
    uint8_t *km2, // 64
    uint8_t *km3, // 64
    uint8_t *session_key, // 64
    const uint8_t *ikm, const uint32_t ikm_len,
    const uint8_t *preamble, const uint32_t preamble_len
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
    hkdfExtract((uint8_t*) NULL,0, ikm, ikm_len, prk);

    // 2. handshake_secret = Derive-Secret(prk, "HandshakeSecret", Hash(preamble))
    uint8_t preamble_secret_label[15] = {'H', 'a', 'n', 'd', 's', 'h', 'a', 'k', 'e', 'S', 'e', 'c', 'r', 'e', 't'};
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
    uint8_t session_key_label[10] = {'S', 'e', 's', 's', 'i', 'o', 'n', 'K', 'e', 'y'};
    ecc_opaque_ristretto255_sha512_3DH_Expand_Label(
        session_key,
        prk,
        session_key_label, sizeof session_key_label,
        preamble_hash, sizeof preamble_hash, Nx
    );

    // 4. Km2 = Derive-Secret(handshake_secret, "ServerMAC", "")
    uint8_t km2_label[9] = {'S', 'e', 'r', 'v', 'e', 'r', 'M', 'A', 'C'};
    ecc_opaque_ristretto255_sha512_3DH_Expand_Label(
        km2,
        handshake_secret,
        km2_label, sizeof km2_label,
        NULL, 0, Nx
    );

    // 5. Km3 = Derive-Secret(handshake_secret, "ClientMAC", "")
    uint8_t km3_label[9] = {'C', 'l', 'i', 'e', 'n', 't', 'M', 'A', 'C'};
    ecc_opaque_ristretto255_sha512_3DH_Expand_Label(
        km3,
        handshake_secret,
        km3_label, sizeof km3_label,
        NULL, 0, Nx
    );

    // cleanup stack memory
    crypto_wipe(prk, sizeof prk);
    crypto_wipe(preamble_hash, sizeof preamble_hash);
    crypto_wipe(handshake_secret, sizeof handshake_secret);
}


// STACKSIZE BEFORE CLEANING: 4384B
// STACKSIZE AFTER CLEANING: 2999B
uint32_t ecc_opaque_ristretto255_sha512_RecoverCredentials(
    uint8_t client_private_key[32],
    uint8_t server_public_key[32],
    uint8_t export_key[64], // 64
    const uint8_t *password, const uint32_t password_len,
    const uint8_t blind[Nok],
    const CredentialResponse *res,
    const uint8_t *server_identity, const uint32_t server_identity_len,
    const uint8_t *client_identity, const uint32_t client_identity_len
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
    uint8_t temp_buffer[128];

    // uint8_t y[64]; // saving space on stack
    #define y temp_buffer  // y is saved on lower 64B of temp_buffer
    Finalize(
        y,
        (uint8_t *) password, password_len,
        (uint8_t *) blind,
        (uint8_t *) res->evaluated_message
    );

    // 2. randomized_pwd = Extract("", Harden(y, params))
    // - Harden(y, params)
    //uint8_t harden_result[Nh]; // saving space on stack
    #define harden_result &temp_buffer[Nh] // harden_result is saved on higher 64B of temp_buffer
    memcpy(harden_result, y, Nh);
    
    // - concat(y, Harden(y, params))
    // We can skip concatination bcs. we actually already concatinate  y || harden_result
    // uint8_t extract_input[2 * Nh];
    // ecc_concat2(extract_input, y, Nh, harden_result, Nh);
    #define extract_input temp_buffer
    
    uint8_t randomized_pwd[Nh];
    //ecc_kdf_hkdf_sha512_extract(randomized_pwd, NULL, 0, extract_input, sizeof extract_input);
    hkdfExtract((uint8_t*) NULL,0, extract_input, sizeof extract_input, randomized_pwd);

  
    // 3. masking_key = Expand(randomized_pwd, "MaskingKey", Nh)
    uint8_t masking_key_info[10] = {'M', 'a', 's', 'k', 'i', 'n', 'g', 'K', 'e', 'y'};
    //uint8_t masking_key[Nh];
    #define masking_key temp_buffer // saving space on stack
    //ecc_kdf_hkdf_sha512_expand(masking_key, randomized_pwd, masking_key_info, sizeof masking_key_info, Nh);
    hkdfExpand(randomized_pwd,Nh,masking_key_info, sizeof masking_key_info, masking_key, Nh);

    // 4. credential_response_pad = Expand(masking_key,
    //      concat(response.masking_nonce, "CredentialResponsePad"), Npk + Ne)
    uint8_t credential_response_pad_label[21] = {'C', 'r', 'e', 'd', 'e', 'n', 't', 'i', 'a', 'l', 'R', 'e', 's', 'p', 'o', 'n', 's', 'e', 'P', 'a', 'd'};
    uint8_t credential_response_pad_info[Nn + 21];
    ecc_concat2(credential_response_pad_info, res->masking_nonce, Nn, credential_response_pad_label, 21);
    uint8_t credential_response_pad[Npk + Ne];
    //ecc_kdf_hkdf_sha512_expand(credential_response_pad, masking_key, credential_response_pad_info, sizeof credential_response_pad_info, Npk + Ne);
    hkdfExpand(masking_key,Nh,credential_response_pad_info, sizeof credential_response_pad_info, credential_response_pad, Npk + Ne);


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
    const uint32_t ret = Recover(
        client_private_key,
        &ignore,
        export_key,
        randomized_pwd, Nh,
        server_public_key,
        &envelope,
        (uint8_t *)server_identity, server_identity_len,
        (uint8_t *)client_identity, client_identity_len
    );

    // cleanup stack memory
    crypto_wipe(y, sizeof y);
    crypto_wipe(randomized_pwd, sizeof randomized_pwd);
    crypto_wipe(masking_key, sizeof masking_key);
    crypto_wipe(credential_response_pad_info, sizeof credential_response_pad_info);
    crypto_wipe(credential_response_pad, sizeof credential_response_pad);
    crypto_wipe(xor_result, sizeof xor_result);
    crypto_wipe(&envelope, sizeof envelope);

    // 7. Output (client_private_key, response.server_public_key, export_key)
    return ret;
}




// STACKSIZE BEFORE CLEANING: 3501B
// STACKSIZE AFTER CLEANING: 3029B
uint32_t ecc_opaque_ristretto255_sha512_3DH_ClientFinalize(
    KE3 *ke3_raw, // 64
    uint8_t session_key[64],
    ClientState *state,
    const uint8_t *client_identity, const uint32_t client_identity_len,
    const uint8_t client_private_key[32],
    const uint8_t *server_identity, const uint32_t server_identity_len,
    const uint8_t server_public_key[32],
    const KE2 *ke2,
    const uint8_t *context, const uint32_t context_len
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

    
    // temporary variable used for efficient manipulation w stack
    uint8_t temp_buff[128];
    

    //uint8_t client_public_key[Npk]; // save space on stack
    #define client_public_key temp_buff
    ScalarMult_(client_public_key, (uint8_t*)client_private_key,(uint8_t*)RISTRETTO255_BASEPOINT_OPRF);

    // 2. preamble = Preamble(client_identity, state.ke1, server_identity, ke2.inner_ke2)
    uint8_t preamble[900]; // 900 should be enough in case IDENTITY_BYTE_SIZE is 128
    const uint32_t preamble_len = ecc_opaque_ristretto255_sha512_3DH_Preamble(
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

    // 1. ikm = TripleDHIKM(state.client_secret, ke2.server_keyshare,
    //     state.client_secret, server_public_key, client_private_key, ke2.server_keyshare)
    
    //uint8_t ikm[96]; //saving space on stack
    #define ikm temp_buff
    ecc_opaque_ristretto255_sha512_3DH_TripleDHIKM(
        ikm,
        state->client_ake_state.client_secret, ke2->auth_response.server_public_keyshare,
        state->client_ake_state.client_secret, server_public_key,
        client_private_key, ke2->auth_response.server_public_keyshare
    );


    // 3. Km2, Km3, session_key = DeriveKeys(ikm, preamble)
    uint8_t km2[64];
    uint8_t km3[64];
    ecc_opaque_ristretto255_sha512_3DH_DeriveKeys(
        km2, km3,
        session_key,
        ikm, 96,
        preamble, preamble_len
    );

    // 4. expected_server_mac = MAC(Km2, Hash(preamble))
    //uint8_t preamble_hash[64]; //save space on stack

    // at this point,lower 64bytes temp_buff of are occupied by preamble_hash
    #define preamble_hash temp_buff 
    //ecc_hash_sha512(preamble_hash, preamble, preamble_len);

    SHA512Context hst;
    SHA512Reset(&hst);
    SHA512Input(&hst, preamble, preamble_len);
    SHA512Result(&hst, preamble_hash);

    //uint8_t expected_server_mac[64];
    // at this point,higher 64bytes temp_buff of are occupied by expected_server_mac
    #define expected_server_mac &temp_buff[64]
    hmac(
        preamble_hash, 64,
        km2,
        sizeof km2,
        expected_server_mac
    );

    // 5. If !ct_equal(ke2.server_mac, expected_server_mac),
    //      raise HandshakeError
    if (!cmp(ke2->auth_response.server_mac, expected_server_mac, Nh)) {
        // cleanup stack memory
        //crypto_wipe(ikm, sizeof ikm);
        crypto_wipe(preamble, sizeof preamble);
        crypto_wipe(km2, sizeof km2);
        crypto_wipe(km3, sizeof km3);
        //crypto_wipe(preamble_hash, sizeof preamble_hash);
        //crypto_wipe(expected_server_mac, sizeof expected_server_mac);
        #undef preamble_hash
        return OPAQUE_ERROR;
    }

    // 6. client_mac = MAC(Km3, Hash(concat(preamble, expected_server_mac))
    //uint8_t client_mac_input[64];
    // at this point,lower 64bytes temp_buff of are occupied by client_mac_input
    // higher 64 bytes of temp_buff are still in use (expected_server_mac)
    #define client_mac_input temp_buff 
    SHA512Reset(&hst);
    SHA512Input(&hst, preamble, preamble_len);
    SHA512Input(&hst, expected_server_mac, 64);
    SHA512Result(&hst, client_mac_input);

    //uint8_t client_mac_[64]; //saving space on stack
    // we no longer need higher 64 bytes of temp_buff to store expected_server_mac
    // so we use them to store client_mac
    #define client_mac_ &temp_buff[64]
    hmac(
        client_mac_input, 64,
        km3,
        sizeof km3,
        client_mac_
    );

    // 7. Create KE3 ke3 with client_mac
    // 8. Output (ke3, session_key)
    memcpy(ke3_raw->client_mac, client_mac_, 64);

    // cleanup stack memory
    //crypto_wipe(ikm, sizeof ikm);
    crypto_wipe(preamble, sizeof preamble);
    crypto_wipe(km2, sizeof km2);
    crypto_wipe(km3, sizeof km3);
    //crypto_wipe(preamble_hash, sizeof preamble_hash);
    //crypto_wipe(expected_server_mac, sizeof expected_server_mac);
    //crypto_wipe(client_mac_input, sizeof client_mac_input);
    //crypto_wipe(client_mac_, sizeof client_mac_);
    #undef client_public_key
    #undef ikm
    #undef preamble_hash
    #undef expected_server_mac
    #undef client_mac_input
    #undef client_mac_

    return OPAQUE_OK;
}




// GENERATE KE3

// STACKSIZE BEFORE CLEANING: 4448B
// STACKSIZE AFTER CLEANING: 3093B
uint32_t ecc_opaque_ristretto255_sha512_GenerateKE3(
    KE3 *ke3_raw,
    uint8_t session_key[64], // client_session_key
    uint8_t export_key[64], // 64
    ClientState *state,
    const uint8_t *client_identity, const uint32_t client_identity_len,
    const uint8_t *server_identity, const uint32_t server_identity_len,
    const KE2 *ke2,
    const uint8_t *context, const uint32_t context_len
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
    const uint32_t recover_ret = ecc_opaque_ristretto255_sha512_RecoverCredentials(
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
    const uint32_t finalize_ret = ecc_opaque_ristretto255_sha512_3DH_ClientFinalize(
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
    crypto_wipe(client_private_key, sizeof client_private_key);
    crypto_wipe(server_public_key, sizeof server_public_key);
//
    // 3. Output (ke3, session_key)
    if (recover_ret == 0 && finalize_ret == 0)
        return OPAQUE_OK;
    else
        return OPAQUE_ERROR;
}