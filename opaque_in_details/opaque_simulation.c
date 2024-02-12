#include "importer.h"

int main(){
    // server initialization
    uint8_t server_identity[0] = {}; // empty for simplicity
    int server_identity_len = 0;

    // rng
    uint8_t oprf_seed[Nh] = {0xf4, 0x33, 0xd0, 0x22, 0x7b, 0x0b, 0x9d, 0xd5, 0x4f, 0x7c, 0x44, 0x22, 0xb6, 0x00, 0xe7, 0x64, 0xe4, 0x7f, 0xb5, 0x03, 0xf1, 0xf9, 0xa0, 0xf0, 0xa4, 0x7c, 0x66, 0x06, 0xb0, 0x54, 0xa7, 0xfd, 0xc6, 0x53, 0x47, 0xf1, 0xa0, 0x8f, 0x27, 0x7e, 0x22, 0x35, 0x8b, 0xba, 0xbe, 0x26, 0xf8, 0x23, 0xfc, 0xa8, 0x2c, 0x78, 0x48, 0xe9, 0xa7, 0x56, 0x61, 0xf4, 0xec, 0x5d, 0x5c, 0x19, 0x89, 0xef};

    uint8_t server_private_key[Nsk]; // 32 bytes
    uint8_t server_public_key[Npk];  // 32 bytes

    DeriveKeyPair(server_private_key,server_public_key);

    // server initialization
    uint8_t client_identity[0] = {}; // empty for simplicity
    int client_identity_len=0;

    uint8_t password[25] = {0x43, 0x6f, 0x72, 0x72, 0x65, 0x63, 0x74, 0x48, 0x6f, 0x72, 0x73, 0x65, 0x42, 0x61, 0x74, 0x74, 0x65, 0x72, 0x79, 0x53, 0x74, 0x61, 0x70, 0x6c, 0x65};
    int password_len = 25;

    // shared values
    uint8_t context[10] = {0x4f, 0x50, 0x41, 0x51, 0x55, 0x45, 0x2d, 0x50, 0x4f, 0x43};
    int context_len = 10;

    // REGISTRATION STAGE

    // 1.) Client registration request
    /*
     * Here Client creates registration request which is 1st step of
     * OPAQUE registration. Check offline_reg_step_1.c for more details.
    */
    RegistrationRequest request;
    uint8_t blind[Nn];

    ClientRegistrationRequest(
        blind, 
        &request, 
        password, password_len
    );

    // 2.) Server registration response
    /*
     * Server creates registration response which is 2st step of
     * OPAQUE registration. Check offline_reg_step_1.c for more details.
    */

    RegistrationResponse response;
    uint8_t credential_identifier[4] = {0x31, 0x32, 0x33,0x34};
    int8_t credential_identifier_len = 4;

    ServerRegistrationResponse(
        &response,
        &request,
        server_public_key,
        credential_identifier, credential_identifier_len,
        oprf_seed
    );

    // 3.) Client registration record
    /*
     * Client creates registration record which is a final step of
     * OPAQUE registration. Registration record contains client_public_key,
     *  masking_key and envelope. Registration record is then sent to the
     * server, where envelope is stored. Clinet also generates export_key, 
     * which is application specific value (not used during OPAQUE). 
    */

    RegistrationRecord record;
    uint8_t export_key[Nh];

    ClientRegistrationRecord(
        &record,
        export_key,
        password, password_len,
        blind,
        &response, // from server
        server_identity, server_identity_len,
        client_identity, client_identity_len
    );


    // LOGIN STAGE
    

    // 1.) Client starts with creation of KE1 message,
    // that subsequently is sent to server.
    KE1 ke1;
    ClientState client_state;

    ClientGenerateKE1(
        &ke1,       // KE1 structure is going to be filled 
        &client_state,     // ClinetState structure is going to be filled 
        password, password_len
    );

    // 2.) Server process KE1 and creates KE2 
    KE2 ke2;
    ServerState server_state;

    ServerGenerateKE2(
        &ke2,
        &server_state,
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

    // 3.) Client process KE2 and creates KE3
    KE3 ke3;
    uint8_t client_session_key[64];

    // ) client AKE3
    ClientGenerateKE3(
        &ke3,
        client_session_key, // client_session_key
        export_key,
        &client_state,
        client_identity, client_identity_len,
        server_identity, server_identity_len,
        &ke2,
        context, context_len
    );


    uint8_t server_session_key[Nx];
    ServerFinish(
        server_session_key,
        &server_state, //server state from KE2
        &ke3
    );

    return 0;
}
