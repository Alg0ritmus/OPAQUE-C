#include "importer.h"

/**
  * This file describes the initial steps, that needs to be taken
  * by both server and clinet when performing OPAQUE protocol.
  * Note that this file also includes all structures and array-size 
  * constants, just to have everything important on one place. 
  * By doing so we believe that this step-by-step tutorial will
  * be more comperhensive.
**/

/**
  * Array-size Constants Used In OPAQUE Protocol 
  * - can be found in opaque.h
  * ---------------------------------------------
  * Nh 64
  * Npk 32
  * Nsk 32
  * Nm 64
  * Nx 64
  * Nok 32
  * Nn 32
  * Nseed 32
  * Noe 32
  * Ne 96
**/


/**
  * All Structures Used In OPAQUE Protocol 
  * - can be found in opaque.h
  * ---------------------------------------
  *
  * typedef struct CleartextCredentials_t{
  *    uint8_t server_public_key[Npk];
  *    uint8_t server_identity[IDENTITY_BYTE_SIZE];
  *    int server_identity_len;
  *    uint8_t client_identity[IDENTITY_BYTE_SIZE];
  *    int client_identity_len;
  *  }CleartextCredentials;
  *
  * typedef struct Envelope_t{
  *    uint8_t  nonce[Nn];     
  *    uint8_t auth_tag[Nm]; 
  *  }Envelope;
  * 
  * 
  * // REGISTRATION MSGs
  * typedef struct RegistrationRequest_t{
  *   uint8_t blinded_message[Noe];
  * } RegistrationRequest;
  * 
  * 
  * typedef struct RegistrationResponse_t{
  *   uint8_t evaluated_message[Noe];
  *   uint8_t server_public_key[Npk];
  * } RegistrationResponse;
  * 
  * 
  * typedef struct RegistrationRecord_t{
  *   uint8_t client_public_key[Npk];
  *   uint8_t masking_key[Nh];
  *   Envelope envelope;
  * } RegistrationRecord;
  * 
  * // LOGIN MSGs
  * 
  * typedef struct CredentialRequest_t{
  *   uint8_t blinded_message[Noe];
  * } CredentialRequest;
  * 
  * 
  * typedef struct CredentialResponse_t{
  *   uint8_t evaluated_message[Noe];
  *   uint8_t masking_nonce[Nn];
  *   uint8_t masked_response[Npk + Nn + Nm];
  * } CredentialResponse;
  * 
  * typedef struct AuthRequest_t{
  *   uint8_t client_nonce[Nn];
  *   uint8_t client_public_keyshare[Npk];
  * } AuthRequest;
  * 
  * 
  * typedef struct KE1_t{
  *   CredentialRequest credential_request;
  *   AuthRequest auth_request;
  * } KE1;
  * 
  * typedef struct AuthResponse_t{
  *   uint8_t server_nonce[Nn];
  *   uint8_t server_public_keyshare[Npk];
  *   uint8_t server_mac[Nm];
  * } AuthResponse;
  * 
  * typedef struct KE2_t{
  *   CredentialResponse credential_response;
  *   AuthResponse auth_response;
  * } KE2;
  * 
  * typedef struct KE3_t{
  *   uint8_t client_mac[Nm];
  * } KE3;
  * 
  * 
  * typedef struct ClientAkeState_t{
  *     uint8_t client_secret[Nsk];
  *     KE1 ke1;
  * } ClientAkeState;
  * 
  * typedef struct ClientState_t{
  *     uint8_t password[512];
  *     int password_len;
  *     uint8_t blind[Nok];
  *     ClientAkeState client_ake_state;
  * } ClientState;
  * 
  * typedef struct ServerState_t{
  *     uint8_t expected_client_mac[Nm];
  *     uint8_t session_key[Nx];
  * } ServerState;
**/

int main()
{
	/** 
    * Initial step of OPAQUE for clinet is to choose clinet's
    * username (or identity in OPAQUE terminology). This is 
    * an application-specific value, e.g., an e-mail address
    * or an account name. If not specified, it defaults to the
    * client's public key.Note that client's identity is not 
    * secret and can be shared, unlike client's password.
  **/
  uint8_t client_identity[0] = {}; //empty for testing purposes
  int client_identity_len=0;


  /**
    * Server's identity is also something publicly known. 
    * This is typically a domain name, e.g., example.com. 
    * If not specified, it defaults to the server's public 
    * key. Server also needs to generate it's primary public
    * and private key. Server also chooses a seed (oprf_seed)
    * of Nh bytes for the OPRF. The server can use server private
    * key and server_public_key with multiple clients. The server
    * can also opt to use different seeds for each client,
    * so long as they are maintained across the registration and online
    * AKE stages, and kept consistent for each client (since 
    * an inconsistent mapping of clients to seeds could leak information.
  **/

  uint8_t server_identity[0] = {}; //empty for testing purposes
  int server_identity_len = 0;
  // oprf seed of Nh (64) bytes, which is a seed used to derive 
  // per-client OPRF keys.
  // this can be randomly generated
  uint8_t oprf_seed[Nh] = {0xf4, 0x33, 0xd0, 0x22, 0x7b, 0x0b, 0x9d, 0xd5, 0x4f, 0x7c, 0x44, 0x22, 0xb6, 0x00, 0xe7, 0x64, 0xe4, 0x7f, 0xb5, 0x03, 0xf1, 0xf9, 0xa0, 0xf0, 0xa4, 0x7c, 0x66, 0x06, 0xb0, 0x54, 0xa7, 0xfd, 0xc6, 0x53, 0x47, 0xf1, 0xa0, 0x8f, 0x27, 0x7e, 0x22, 0x35, 0x8b, 0xba, 0xbe, 0x26, 0xf8, 0x23, 0xfc, 0xa8, 0x2c, 0x78, 0x48, 0xe9, 0xa7, 0x56, 0x61, 0xf4, 0xec, 0x5d, 0x5c, 0x19, 0x89, 0xef};

  uint8_t server_private_key[Nsk]; // 32 bytes
  uint8_t server_public_key[Npk];  // 32 bytes

  // server's private and public keys can be generated
  // using DeriveKeyPair()
  DeriveKeyPair(server_private_key,server_public_key);

  /**
    * Context is the shared parameter used to construct the preamble
    * in login phase. This parameter SHOULD include any 
    * application-specific configuration information or parameters
    * that are needed to prevent cross-protocol or downgrade attacks.
  **/

  uint8_t context[10] = {0x4f, 0x50, 0x41, 0x51, 0x55, 0x45, 0x2d, 0x50, 0x4f, 0x43};
  int context_len = 10;
	return 0;
}