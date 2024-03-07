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
//  - ServerState *state;
//	- const KE3 *ke3;


// Variables that the server generates in this phase:
//  - uint8_t server_session_key[Nx];

/*
 * The last step of the entire OPAQUE protocol is on the server-side. 
 * The server needs to verify if the client_mac (in the KE3 message) 
 * is identical to the expected_client_mac. If so, the client and 
 * server can use the session_key to encrypt their conversation.
*/

int main()
{
	uint8_t server_session_key[Nx];
    ecc_opaque_ristretto255_sha512_ServerFinish(
        server_session_key,
        &server_state, //server state from KE2
        &ke3
    );
	return 0;
}