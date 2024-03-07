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
//  - RegistrationRequest request;
//  - uint8_t blind[Nn];


/**
  * OPAQUE is defined as the composition of two functionalities 
  * an OPRF (Oblivious Pseudorandom Function) and an AKE protocol. 
  * It can be seen as a "compiler" for transforming any AKE protocol
  * (with KCI security and forward secrecy; see below) into a secure
  * aPAKE (Asymmetric (or Augmented) Password Authenticated Key Exchange)
  * protocol. This file describes first step of registration phase
  * of OPAQUE protocol. Note that registration phase represents
  * OPRF part. Registration is the only stage in OPAQUE that requires a server-
  * authenticated channel with confidentiality and integrity: either
  * physical, out-of-band, PKI-based, etc.
  *
  * The client inputs its credentials, which include its password and
  * user identifier, and the server inputs its parameters, which include
  * its private key and other information.
  *
  * The client output of this stage is a single value export_key that the
  * client may use for application-specific purposes, e.g., as a
  * symmetric key used to encrypt additional information for storage on
  * the server.  The server does not have access to this export_key.

  * The server output of this stage is a record corresponding to the
  * client's registration that it stores in a credential file alongside
  * other clients registrations as needed.
**/

int main()
{
/** 
  *   Registration phase starts client with generating registration request.
  *   Registration request is then sent to Server.
  *   Client can generate reg. req. using ClientRegistrationRequest().
  *   Inputs and outputs of such function are:
  *     Input:
  *       - password, an opaque byte string containing the client's password.
  *
  *     Output:
  *       - request, a RegistrationRequest structure.
  *       - blind, an OPRF scalar value.
  **/

  RegistrationRequest request;
  uint8_t blind[Nn];
  uint8_t password[25] = {0x43, 0x6f, 0x72, 0x72, 0x65, 0x63, 0x74, 0x48, 0x6f, 0x72, 0x73, 0x65, 0x42, 0x61, 0x74, 0x74, 0x65, 0x72, 0x79, 0x53, 0x74, 0x61, 0x70, 0x6c, 0x65};
  int password_len = 25;


  // 1.1) Client create req.
  ClientRegistrationRequest(
    blind, 
    &request, 
    password, password_len
  );

/**
  * Registration part of OPAQUE protocol detailed:
  * --------------------------------------------------------
  *
  *  OPAQUE registration phase diagram:
  * -----------------------------------
	*
  *    creds                                   parameters
  *      |                                         |
  *      v                                         v
  *    Client                                    Server
  *    ------------------------------------------------
  *          1.1) registration request // discussed in this file
  *             ------------------------->
  * 1.2) registration response //discussed in file offline_reg_step_2.c
  *             <-------------------------
  *      1.3) record //discussed in file offline_reg_step_3.c
  *             ------------------------->
  *   ------------------------------------------------
  *      |                                         |
  *      v                                         v
  *  export_key                                 record
  *
  *
  *  OPAQUE registration phase pseudocode:
  * --------------------------------------
  * 
  * def CreateRegistrationRequest(password):
  *      (blind, blinded_element) = Blind(password)
  *      blinded_message = SerializeElement(blinded_element)
  *      Create RegistrationRequest request with blinded_message
  *      return (request, blind)
  *
  * Math behind OPRF (registration part of OPAQUE protocol:
  * -------------------------------------------------------
  *
  * Note that we are using Blind function, which is part 
  * of OPRF protocol. Oblivious Pseudorandom Function (OPRF)
  * is a two-party protocol between client and server for computing a PRF, 
  * where the PRF key is held by the server and the input to the function
  * is provided by the client. The client does not learn anything about the
  * PRF other than the obtained output and the server learns nothing
  * about the client's input or the function output. In other words
  * OPRF is a protocol by which two parties compute a function F(key, x)
  * that is deterministic but outputs random-looking values. 
  * One party inputs the value x, and another party inputs the key - the party
  * who inputs x learns the result F(key, x) but not the key, and the party
  * providing the key learns nothing.
  * 
  * Essentially, math behind OPRF is pretty streight forward
  * (in OPRF terminology known as Signing Phase), 
  * we will refer to this steps later as "OPRF Signing phase":
  *
  *     0) Client hold input 't' (this could be password), Server holds secret key 'x'
  *     
  *     1) Client generates random 'blind' value, 
  *     which is just a random number from GF (Galois Field)           
  *                                                
  *     2) Client computes T = H_1(t) and then blinds it by computing rT      
  *                                                
  *     3) Client sends M = rT to Server, note that M is known
  *      as blinded_element in our case
  *  
  *     4) Server computes Z = xM and returns Z to Clinet
  *     
  *     5) Clinet computes (1/r)*Z = xT = N and stores the pair (t,N) 
  *     for some point in the future

  * Where H_1() is collision resistant hash function. Note that output 
  * of H_1() in this case is acctually serialized ristretto255_point 
  * (32-byte array) and 'r' is just a random scalar < L.
  * 
  * We achieved serialized ristretto255_point by combining 2 functions:
  *     1) expand_message_xmd_sha512() -> to get uniformly distributed hash digest (bytes) 
  *     [https://www.rfc-editor.org/rfc/rfc9380.html#section-5.3.1]
  *     2) ristretto255 function called hash_to_group() to map hash digest to ristretto255 group 
  *     [https://www.ietf.org/archive/id/draft-irtf-cfrg-ristretto255-decaf448-08.html#section-4.3.4]
  * Also note that Blind() consists of steps 1,2 and 3. Also we can skip Serialize Function (see pseudocode),
  * since we used ristretto255 hash_to_group function which map hash into serialized element. 
  * We will refer to "OPRF Signing phase" later in files offline_reg_step_2.c and offline_reg_step_3.c
**/
	return 0;
}