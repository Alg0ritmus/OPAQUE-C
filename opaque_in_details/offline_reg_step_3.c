#include "importer.h"

// CLIENT side

// Variables that the client already has:
//  - uint8_t *password;
//  - int password_len;
//  - uint8_t *server_identity;
//  - int server_identity_len;
//  - uint8_t client_identity;
//  - int client_identity_len;
//  - uint8_t blind[Nn];
//  - RegistrationResponse response;

// Variables that the clinet generates in this phase:
//  - RegistrationRecord record;
//  - uint8_t export_key[Nh];


int main()
{
	/** 
    * This file describes last step of OPAQUE offline registration
	* phase, which is registration record (see offline_reg_step_1.c).
    * Creation of registration record is made on clinet.
    * RegistrationRecord can be created with function
    * called ClientRegistrationRecord()
    *  
		*	Input:
		*		- password, an opaque byte string containing the client's password.
		*		- blind, an OPRF scalar value.
		*		- response, a RegistrationResponse structure.
		*		- server_identity, the optional encoded server identity.
		*		- client_identity, the optional encoded client identity.
		*	
		*	Output:
		*		- record, a RegistrationRecord structure.
		*		- export_key, an additional client key.
	**/

  // 1.3) Server create resp.
  ClientRegistrationRecord(
    &record,
    export_key,
    password, password_len,
    blind,
    &response, // from server
    server_identity, server_identity_len,
    client_identity, client_identity_len
  );

/**
  * Registration part of OPAQUE protocol detailed:
  * --------------------------------------------------------
  * def FinalizeRegistrationRequest(password, blind, response, server_identity, client_identity):
  *  evaluated_element = DeserializeElement(response.evaluated_message)
  *  oprf_output = Finalize(password, blind, evaluated_element)
  *
  *  stretched_oprf_output = Stretch(oprf_output)
  *  randomized_password = Extract("", concat(oprf_output, stretched_oprf_output))
  *
  *  (envelope, client_public_key, masking_key, export_key) =
  *    Store(randomized_password, response.server_public_key,
  *          server_identity, client_identity)
  *  Create RegistrationRecord record with (client_public_key, masking_key, envelope)
  *  return (record, export_key)

  * As you can see in "FinalizeRegistrationRequest" pseudocode, Client starts with
  * deserializing evaluated element received from Server. Since, we already did this step
  * (client already has a byte-array ristretto255 element) we can skip this step.
  * After that we use OPRF function called "Finalize()", which is essentially computing
  * unblindedElement = (1/r)*Z. In other words it performs: blind^-1 * evaluatedElement. 
  * There's one more step not mentioned previously and that is to create hash digest from (1/r)*Z,
  * which can be written as:
  *   H_( len(t) || t || len(unblindedElement) || unblindedElement || "Finalize")
     
  * Note that 't' is client input mentioned previously in step 0. 
  * In real-world this is usually client's password. More information about 
  * OPRF (version 0x00) can be found in official draft 
  * [ https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-21 ].

  * This is all from OPRF side, but OPAQUE does not stop here yet. 
  * In process of OPAQUE offline registration there's one more step, an Envelope creation.
  * OPAQUE makes use of a structure called Envelope to manage client credentials. 
  * The client creates its Envelope (using function called "Store()") on registration 
  * and sends it to the server for storage. On every login, the server sends this Envelope 
  * to the client so it can recover its key material for use in the AKE (Authenticated Key Exchange). 
  
  * Note that server stores only envelope (created and secured by clients authentification 
  * key "expanded" (using hkdfExpand function) from randomized password).
  * This is core of OPAQUE protocol, servers learn nothing about
  * client's credential. Recover of envelope is perform later in login stage (AKE3 message).

  *  The key recovery mechanism defines its Envelope as follows:

      struct {
        uint8 nonce[Nn];
        uint8 auth_tag[Nm];
      } Envelope;

    *nonce: A randomly-sampled nonce of length Nn, used to protect this Envelope.

    *auth_tag: An authentication tag protecting the contents of the envelope, 
    covering the envelope nonce and CleartextCredentials. 
  *  There are mechanisms to create (client side) and recover 
  *  (server-side) an Envelope. 

  *  Function called "Store()" is used for Envelope creation and Recover used 
  *  for Envelope recovery. These functions will be detaily described later. 
  *  Now back to last step of OPAQUE's offline registration. 
  *  After we compute oprf_output we perform a strengthen of oprf_output using KSF 
  *  function such as Argon2id or scrypt. In our implementation we use Identity, 
  *  which can be described as follows:

  *    msg = IdentityStretch(msg),

  *  that means we can simply skip this process (or use something like memcpy).
  *  Next we extract a 'randomized_password' using hkdf function from 
  *  oprf_output || strengthen_oprf_output. In our case oprf_output || oprf_output
  *  since we used Identity.
  *  Lastly client create Record(Envelope,client_public_key,masking_key) as well as 
  *  export_key using Store() function.
  *  Note that Record is datastructure that contains Envelope, client_public_key and masking_key.
**/ 

	return 0;
}