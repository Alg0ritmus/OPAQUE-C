#include "importer.h"

// CLIENT side

// Variables that the client already has:
//  - uint8_t *server_identity;
//  - int server_identity_len;
//  - uint8_t client_identity;
//  - int client_identity_len;
//  - ClientState *state;
//  - KE2 *ke2;
//  - uint8_t *context;
//  - int context_len;


// Variables that the client generates in this phase:
//  - KE3 *ke3;
//  - uint8_t client_session_key[Nh];
//  - uint8_t export_key[Nh];


int main()
{

  /**
  * This file focuses on generating 3. AKE message.
  * KE3 is generated on server-side and this process
  * can be partially called as client-envelope-recovery stage.
  * The process starts with client, by generating KE3 message
  * using ClientGenerateKE3().
  *
  * Input:
  *   - client_identity, the optional encoded client identity, which is set
  *     to client_public_key if not specified.
  *   - server_identity, the optional encoded server identity, which is set
  *     to server_public_key if not specified.
  *   - ke2, a KE2 message structure.
  * Output:
  *   - ke3, a KE3 message structure.
  *   - session_key, (client_session_key) the session's shared secret.
  *   - export_key, an additional client key.
**/

  KE3 ke3;
  uint8_t client_session_key[64];

  // 2.3) client AKE3
  ClientGenerateKE3(
    &ke3,
    client_session_key, // client_session_key
    export_key,
    &state,
    client_identity, client_identity_len,
    server_identity, server_identity_len,
    &ke2,
    context, context_len
  );

/** 
* Last step of AKE,online login phase (AKE3)
* ------------------------------------------
*
* Pseudocode of GenerateKE3()
* -----------------------------------------
*
* def GenerateKE3(client_identity, server_identity, ke2):
*       (client_private_key, cleartext_credentials, export_key) =
*         RecoverCredentials(state.password, state.blind, ke2.credential_response,
*                            server_identity, client_identity)
*       (ke3, session_key) =
*         AuthClientFinalize(cleartext_credentials, client_private_key, ke2)
*       return (ke3, session_key, export_key)
*
*
* Third step of AKE is initiated on Clinet. Client needs to recover 
* his credentials using RecoverCredentials() function. The output 
* of RecoverCredentials function is client_private_key (in our impl. 
* also public key), cleartext_credentials, export_key.
*	As we mentioned previously export_key could be used for 
* application specific purposes e.g. encrypted remote storage 
* example. Note that RecoverCredentials() contains OPRF step of Finalization,
* which is essentially computing unblindedElement = (1/r)*Z. 
* In other words it performs: blind^-1 * evaluatedElement. 
* This is very similar to process of Finalize Registration Request 
* described in step 1.3 (in file offline_reg_step_3.c), 
* except now client does not create an Envelope, but rather Recover envelope.
*
*	After retrieving values from RecoverCredentials() function, client needs to create KE3
*	message and retrieve session_key using AuthClientFinalize(). 
*  This step is very similar to AuthServerRespond() used by server when generating KE2 message,
*  which is:
*		1.) TripleDHIKM simply returns ikm (input key material)
*			1.1) dh1 = sk1 * pk1 		// client_secret_key * server_public_keyshare
*	     	1.2) dh2 = sk2 * pk2		// client_secret_key * server_public_keyshare
*	     	1.3) dh3 = sk3 * pk3		// client_private_key * server_public_keyshare
*	     	1.4) ikm = dh1 || dh2 || dh3
*
*	    2.) construct preamble = "OPAQUEv1-" || len(context) || context
*		|| len(client_identity) || client_identity || ke1
*		|| len(server_identity) || server_identity
*		|| KE2
*
*	    3.) Derive km2, km3, session_key keys from preamble and ikm
*	     - basically this is nothing else than usage of hkdfExtract and hkdmExpand multiple time, just like when generating KE2 message.
*
*	    4.) calculate expected server mac:
*	     	expected_server_mac = hmac(km2, Hash(preamble))
*
*	     	and if ke2.server_mac is not equal to expected_server_mac,
*	     	then raise error.
*
*	    5.) calculate client mac (client_mac is parto of AKE3 message):
*	     	client_mac = hmac(km3, Hash(preamble || expected_server_mac))
**/
	return 0;
}