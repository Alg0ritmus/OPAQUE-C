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

// CLIENT side

// Variables that the client already has:
//  - uint8_t *password;
//  - int password_len;


// Variables that the client generates in this phase:
//  - KE1 *ke1;
//  - ClientState *state;

int main()
{
/**
  * In this second stage, a client obtains credentials previously registered 
  * with the server, recovers private key material using the password, 
  * and subsequently uses them as input to the AKE protocol. 
  * As in the registration phase, the client inputs its credentials, 
  * including its password and user identifier, and the server inputs 
  * its parameters and the credential file record corresponding to the 
  * client. The client outputs two values, an export_key (matching that
  * from registration) and a session_key, the latter of which is the primary
  * AKE output. The server outputs a single value session_key that matches 
  * that of the client. Upon completion, clients and servers can use these
  * values as needed.
  *
  *
  * This section describes the online authenticated key exchange 
  * protocol flow, message encoding, and helper functions. This stage is 
  * composed of a concurrent OPRF and key exchange flow. The key exchange
  * protocol is authenticated using the client and server credentials
  * established during registration.
  *
  * In the end, the client proves its knowledge of the password, 
  * and both client and server agree on a mutually authenticated 
  * shared secret key and any optional application information
  * exchange during the handshake.
  *
  * The client receives two outputs, a session secret and an export key. 
  * The export key is only available to the client and may be used for
  * additional application-specific purposes (e.g. use as secret key for 
  * encrypting data and store at remote, perhaps server's, storage). 
  * Clients and servers MUST NOT use the output export_key before 
  * authenticating the peer in the authenticated key exchange protocol. 
  * The server receives a single output, a session secret matching the client's.

  * As discussed above, login stage is initiated by client. Client constructs 
  * and sends 1.AKE message to the server. Such message is constructed using
  * ClientGenerateKE1().
  *
  * Input:
  *   - password, an opaque byte string containing the client's password.
  *
  * Output:
  *   - ke1, a KE1 message structure.
**/

  // 2.1) GenerateKE1 (AKE1)
  KE1 ke1;
  ClientState state;

  ClientGenerateKE1(
    &ke1,       // KE1 structure is going to be filled 
    &state,     // ClinetState structure is going to be filled 
    password, password_len
  );

/**
  * Note that clinet not only needs to generate KE1 message, but also
  * generates his state. From now, both client and server may use 
  * implicit internal state objects to keep necessary material for the OPRF
  * and AKE, ClientState and ServerState, respectively. You can find all
  * used structures in file initial_configuration.c
  *
  * ClinetState contains materials like:
  *   password, password_len, blind and ClientAkeState, which consists of
  *   client_secret, KE1 structure.
  *
**/

/**
  * Online login phase detailed:
  * --------------------------------------------------------
  *    Client                                         Server
  *   ------------------------------------------------------
  *    ke1 = GenerateKE1(password)
  *                             ke1
  *                ------------------------->
  *      ke2 = GenerateKE2(server_identity, server_private_key,
  *                      server_public_key, record,
  *                      credential_identifier, oprf_seed, ke1)
  *                             ke2
  *                <-------------------------
  *        (ke3,
  *      session_key,
  *      export_key) = GenerateKE3(client_identity,
  *                                 server_identity, ke2)
  *                             ke3
  *                ------------------------->
  *                          session_key = ServerFinish(ke3)
  *
  * The login phase is very similar. It starts the same way as 
  * registration — with an OPRF flow. However, on the server side,
  * instead of generating a new OPRF key, Server instead looks up 
  * the one he created during Clinet's registration. He does this
  * by looking up Client’s username (which he provides in the first message),
  * and retrieving his record of Client. 
  * This record contains client's public key, his encrypted envelope,
  * and Server’s OPRF key for Client.
  *
  * Server also sends over the encrypted envelope which Client
  * can decrypt with the output of the OPRF flow. 
  * (If decryption fails, Client aborts the protocol — this likely
  * indicates that clinet typed his password incorrectly, 
  * or Server isn’t who he says he is). If decryption succeeds, 
  * clinet now has his own secret key and Server’s public key. 
  * Client inputs these into an AKE protocol with Server, 
  * who, in turn, inputs his private key and clinet's public key, 
  * which gives them both a fresh shared secret key.
  *
  *
  * Generate AKE1 message - pseudocode & description
  * ------------------------------------------------
  *   def GenerateKE1(password):
  *      request, blind = CreateCredentialRequest(password)
  *      state.password = password
  *      state.blind = blind
  *      ke1 = AuthClientStart(request)
  *      return ke1
  *
  * First step of GenerateKE1 is to generate request and blind element.
  * Request is a structure which contains blinded_message (blinded_element). 
  * In other words function CreateCredentialRequest perform Blinding phase 
  * (similarly like in registration phase), so client needs to generate 
  * random blind value, computes T = H_1(t), where 't' is usually client's
  * password and then blinds it by computing rT.
  *
  * Second step is to generate/fill up KE1 structure as well as Clients's state.
  *
  *  struct {
  *    uint8_t client_nonce[Nn];       // random value < L
  *    uint8_t client_public_keyshare[Npk];  // clinet's public key generated by AuthClientStart()
  *  } AuthRequest;
  *
  *  struct {
  *    uint8_t blinded_message[Noe];     // blinded_element from 1'st step -> CreateCredentialRequest()
  *  } CredentialRequest; 
  *
  *  struct {
  *      uint8_t client_secret[Nsk];     // clinet's private key generated by AuthClientStart()
  *      KE1 ke1;
  *  } ClientAkeState;
  *
  *  struct {
  *    CredentialRequest credential_request; 
  *    AuthRequest auth_request;
  *  } KE1;
  *
  *  struct {
  *      uint8_t password[512]; 
  *      int password_len;
  *      uint8_t blind[Nok];         // random value < L
  *      ClientAkeState client_ake_state;
  *  } ClientState;
  *
  *
  * In summary, CreateCredentialRequest() generates blind (random number) 
  * and blinded_element which is Hash(t) * blind, where 't' is usually 
  * client's password.
  *
  * AuthClientStart() essentially generates public and private
  * client's key using randomly generated seed. When Client obtains 
  * those values, he fill up ClientState and KE1 structure.  
**/
	return 0;
}