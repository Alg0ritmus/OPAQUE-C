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
  * OPAQUE STRUCTURES 
  * -----------------
  * OPAQUE uses specific structures, that are implemented in RFC
  * 
  *
**/

// CleartextCredentials structure
struct CleartextCredentials{
     uint8_t server_public_key[Npk];
     uint8_t server_identity[IDENTITY_BYTE_SIZE];
     int server_identity_len;
     uint8_t client_identity[IDENTITY_BYTE_SIZE];
     int client_identity_len;
   };


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
    struct CleartextCredentials *credentials,
    uint8_t server_public_key[Npk],
    uint8_t client_public_key[Npk], // QUESTION: how to propperly indent this ?
    uint8_t server_identity[IDENTITY_BYTE_SIZE], int server_identity_len,
    uint8_t client_identity[IDENTITY_BYTE_SIZE], int client_identity_len
  ) {

  int has_server_identity, has_client_identity;
  has_server_identity = 0; has_client_identity = 0;

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
  if (!has_server_identity){
    memcpy(credentials->server_identity, server_public_key, server_identity_len);
  }

  if (!has_client_identity){
    memcpy(credentials->client_identity, client_public_key, client_identity_len);
  }

  memcpy(credentials->server_public_key, server_public_key, Npk);
}


// https://github.com/aldenml/ecc/blob/fedffd5624db6d90c659864c21be0c530484c925/src/opaque.c#L194C1-L211C2
static int serializeCleartextCredentials(uint8_t *out, struct CleartextCredentials *credentials) {
    const int len = Npk + 2 + credentials->server_identity_len + 2 + credentials->client_identity_len;

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
    printf("idzeee\n");
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
    struct Envelope *envelope, 
    uint8_t client_public_key[Npk],
    uint8_t masking_key[Nh],
    uint8_t export_key[Nh],
    uint8_t *randomized_password, int randomized_password_len,
    uint8_t server_public_key[Npk],
    uint8_t *server_identity, int server_identity_len,
    uint8_t *client_identity, int client_identity_len
    ) {

    uint8_t envelope_nonce[Nn];


    struct CleartextCredentials clear_cred; // QUESTION: Can I do it in 1 line?
    struct CleartextCredentials *cleartext_credentials = &clear_cred; // Do I need this line?


    // QUESTION: we need to use TRNG multiple time here,
    // do we wanna use Cyclone? e.g.
    // https://github.com/Oryx-Embedded/CycloneCRYPTO/blob/master/hardware/ra2/ra2_crypto_trng.c#L51C9-L51C56 
    
    rnd(envelope_nonce,0x00);    // envelope_nonce = random(Nn)

 
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


    CreateCleartextCredentials(cleartext_credentials, server_public_key, client_public_key,server_identity,server_identity_len, client_identity, client_identity_len);

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
  * REGISTRATION PART (PHASE 1)
  * ---------------------------
  * Registration part consists of 3 functions:
  *         - (request, blind) = CreateRegistrationRequest(password)
  *         - response = CreateRegistrationResponse(request, server_public_key, credential_identifier, oprf_seed)
  *         - (record, export_key) = FinalizeRegistrationRequest(response, server_identity, client_identity)
  *
  *
**/