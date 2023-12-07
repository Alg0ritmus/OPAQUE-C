// ******************************************************************
// ----------------- TECHNICAL UNIVERSITY OF KOSICE -----------------
// ---Department of Electronics and Multimedia Telecommunications ---
// -------- FACULTY OF ELECTRICAL ENGINEERING AND INFORMATICS -------
// ------------ THIS CODE IS A PART OF A MASTER'S THESIS ------------
// ------------------------- Master thesis --------------------------
// -----------------Patrik Zelenak & Milos Drutarovsky --------------
// ---------------------------version 0.0.1 -------------------------
// --------------------------- 14-10-2023 ---------------------------
// ******************************************************************

#include "server_side.h"
#include "client_side.h"


// 1) step, skus spustita overit vsteko v tomto file,
// 2) rozdel files na client/server_app
// 3) sprav TCP komunikaciu
// 4) vypis nejake veci do outputu (mozno)
// 5) zapis veci do suboru
int main(){
  srand(0x12);

  // 1) registration
  // -----------------

  // publicly known?
  uint8_t server_identity[0] = {};
  int server_identity_len = 0;
  uint8_t client_identity[0] = {};
  int client_identity_len=0;
  uint8_t context[10] = {0x4f, 0x50, 0x41, 0x51, 0x55, 0x45, 0x2d, 0x50, 0x4f, 0x43};
  int context_len = 10;


  // CLIENT VARIABLES:
  // input:
  //uint8_t password[25] = {0x43, 0x6f, 0x72, 0x72, 0x65, 0x63, 0x74, 0x48, 0x6f, 0x72, 0x73, 0x65, 0x42, 0x61, 0x74, 0x74, 0x65, 0x72, 0x79, 0x53, 0x74, 0x61, 0x70, 0x6c, 0x65}; 
  //int password_len=25;

  uint8_t password[9] = "topSecret"; 
  int password_len=9;
  
  // output:
  RegistrationRequest request;
  uint8_t blind[32];



  // SERVER VARIABLES:
  // input:
  uint8_t server_public_key[Npk] = {0xb2,0xfe,0x7a,0xf9,0xf4,0x8c,0xc5,0x02,0xd0,0x16,0x72,0x9d,0x2f,0xe2,0x5c,0xdd,0x43,0x3f,0x2c,0x4b,0xc9,0x04,0x66,0x0b,0x2a,0x38,0x2c,0x9b,0x79,0xdf,0x1a,0x78};
  uint8_t credential_identifier[4] = {0x31, 0x32, 0x33,0x34};
  int credential_identifier_len= 4;
  uint8_t oprf_seed[Nh] = {0xf4, 0x33, 0xd0, 0x22, 0x7b, 0x0b, 0x9d, 0xd5, 0x4f, 0x7c, 0x44, 0x22, 0xb6, 0x00, 0xe7, 0x64, 0xe4, 0x7f, 0xb5, 0x03, 0xf1, 0xf9, 0xa0, 0xf0, 0xa4, 0x7c, 0x66, 0x06, 0xb0, 0x54, 0xa7, 0xfd, 0xc6, 0x53, 0x47, 0xf1, 0xa0, 0x8f, 0x27, 0x7e, 0x22, 0x35, 0x8b, 0xba, 0xbe, 0x26, 0xf8, 0x23, 0xfc, 0xa8, 0x2c, 0x78, 0x48, 0xe9, 0xa7, 0x56, 0x61, 0xf4, 0xec, 0x5d, 0x5c, 0x19, 0x89, 0xef};

  // output:
  RegistrationResponse response;
  
  RegistrationRecord record;
  uint8_t export_key[Nh];


  // 1.1) Client create req.
  ClientRegistrationRequest(
    blind, 
    &request, 
    password, password_len
  );


  // 1.2) Server create resp.
  ServerRegistrationResponse(
    &response,
    &request,
    server_public_key,
    credential_identifier, credential_identifier_len,
    oprf_seed
  );


  // 1.3 Client create record
  ClientRegistrationRecord(
    &record,
    export_key,
    password, password_len,
    blind,
    &response, // from server
    server_identity, server_identity_len,
    client_identity, client_identity_len
  );











  // 2) login
  // ----------------

  // CLIENT VARIABLES:
  // input:
  // password, password_len  

  // output:
  KE1 ke1;
  ClientState state;

  KE3 ke3;
  uint8_t client_session_key[64];
  //uint8_t export_key[64];
  // server session_key
  uint8_t session_key_S[Nx];


  // SERVER VARIABLES:
  // input:
  uint8_t server_private_key[32] = {0x47, 0x45, 0x1a, 0x85, 0x37, 0x2f, 0x8b, 0x35, 0x37, 0xe2, 0x49, 0xd7, 0xb5, 0x41, 0x88, 0x09, 0x1f, 0xb1, 0x8e, 0xdd, 0xe7, 0x80, 0x94, 0xb4, 0x3e, 0x2b, 0xa4, 0x2b, 0x5e, 0xb8, 0x9f, 0x0d};

  // output
  KE2 ke2;
  ServerState state_raw;



  // 2.1) client AKE1
  ClientGenerateKE1(
    &ke1,
    &state,
    password, password_len
  );

  // 2.2) server AKE2
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

  // 2.4) server final check
  int check = ServerFinish(
    session_key_S,
    &state_raw,
    &ke3
  );

  printf("Server check:%d\n",check);
  printf("Server session key:\n");
  print_32(session_key_S);
  printf("Client session key:\n");
  print_32(client_session_key);

  return 0;

}



