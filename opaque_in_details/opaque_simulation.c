// ******************************************************************
// ----------------- TECHNICAL UNIVERSITY OF KOSICE -----------------
// ---Department of Electronics and Multimedia Telecommunications ---
// -------- FACULTY OF ELECTRICAL ENGINEERING AND INFORMATICS -------
// ------------ THIS CODE IS A PART OF A MASTER'S THESIS ------------
// ------------------------- Master thesis --------------------------
// -----------------Patrik Zelenak & Milos Drutarovsky --------------
// ---------------------------version 1.1.0 -------------------------
// --------------------------- 20-03-2024 ---------------------------
// ******************************************************************

#include "importer.h"

static void print_structure(const uint8_t* o, const uint32_t size){

    for (uint32_t i=0;i<size;i++){
        if(i%8==0){printf("\n   ");}
        printf("%02hx ", o[i]);   
    }
    printf("\n\n");
}

int main(){
    printf("0.) --- INIT STAGE --- \n");
    // server initialization
    uint8_t *server_identity= NULL; // empty for simplicity
    uint32_t server_identity_len = 0;

    // rng
    uint8_t oprf_seed[Nh] = {
        0xf4, 0x33, 0xd0, 0x22, 0x7b, 0x0b, 0x9d, 0xd5, 
        0x4f, 0x7c, 0x44, 0x22, 0xb6, 0x00, 0xe7, 0x64, 
        0xe4, 0x7f, 0xb5, 0x03, 0xf1, 0xf9, 0xa0, 0xf0, 
        0xa4, 0x7c, 0x66, 0x06, 0xb0, 0x54, 0xa7, 0xfd, 
        0xc6, 0x53, 0x47, 0xf1, 0xa0, 0x8f, 0x27, 0x7e, 
        0x22, 0x35, 0x8b, 0xba, 0xbe, 0x26, 0xf8, 0x23, 
        0xfc, 0xa8, 0x2c, 0x78, 0x48, 0xe9, 0xa7, 0x56, 
        0x61, 0xf4, 0xec, 0x5d, 0x5c, 0x19, 0x89, 0xef};

    printf("\n0.1) Server generates oprf_seed(64 bytes) from rng:\n");
    printf("    > Oprf_seed is also known as 'salt' and it is used to derive\n \
    keys and other values by sever:");
    print_structure(oprf_seed,Nh);

    uint8_t server_private_key[Nsk]; // 32 bytes for private key
    uint8_t server_public_key[Npk];  // 32 bytes for public key

    DeriveKeyPair(server_private_key,server_public_key);
    printf("\n0.2) Server generates server_private_key and server_public_key:\n");
    printf("    > Those keys are used in various phases including 3Diffie-Hellman exchange in login phase\n \
    in other words those keys needs to be stored by server as well as oprf_seed\n");
    printf("    > Server private key of lenght 32bytes:");
    print_structure(server_private_key,Nsk);
    printf("    > Server public key of lenght 32bytes:");
    print_structure(server_public_key,Npk);

    // server initialization
    uint8_t *client_identity = NULL; // empty for simplicity

    uint32_t client_identity_len=0;

    uint8_t password[25] = {
        0x43, 0x6f, 0x72, 0x72, 0x65, 0x63, 0x74, 0x48, 0x6f, 0x72, 
        0x73, 0x65, 0x42, 0x61, 0x74, 0x74, 0x65, 0x72, 0x79, 0x53, 
        0x74, 0x61, 0x70, 0x6c, 0x65};
    uint32_t password_len = 25;
    printf("\n0.3) Client choose its password:");
    printf("\n    > Client password of length 25 bytes was chosen:");
    print_structure(password,password_len);


    // shared values
    uint8_t context[10] = {0x4f, 0x50, 0x41, 0x51, 0x55, 0x45, 0x2d, 0x50, 0x4f, 0x43};
    uint32_t context_len = 10;

    printf("\n0.4) Both agree upon shared context:");
    printf("\n    > In this case, context is 25 bytes long\n \
    check initial_configuration_step_0.c for more info about context:");
    print_structure(context,context_len);


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
    printf("1.) --- REGISTRATION STAGE --- \n");
    printf("\n1.1) Client generates its 'blind' and 'RegistrationRequest':");
    printf("\n    > A 'blind' is a value that is used to blind Hashed password\n in blind signing process \
    in OPAQUE, blind is 32 bytes long:");
    print_structure(blind,Nn);
    printf("    > A RegistrationRequest is a structure that holds 'blinded_message'\n \
    ,essentially blinded_message = Hash(password) * blind, and it is also 32 bytes long:");
    print_structure((uint8_t*) &request,Noe);

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

    printf("\n1.2) Server process client request and generates its 'RegistrationResponse':");
    printf("\n    > A RegistrationResponse contains 'evaluated_message' and  'server_public_key'");
    printf("\n    > A 'evaluated_message' is essentially signed 'blinded_message' of length 32 bytes:");
    print_structure((uint8_t*) &response.evaluated_message,Noe);
    printf("\n    > A 'server_public_key', which was generated previously has 32 bytes\n");
    print_structure((uint8_t*) &response.server_public_key,Npk);

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

    printf("1.3) Client processes server response and generates 'export_key' and 'RegistrationRecord',\n \
    which contains client_public_key, masking_key and Envelope:\n");
    
    printf("\n    > An 'export_key' is just a key for application  \
    specific purposed, non needed actually in OPAQUE Auth process \
    its length is 32 bytes:\n");
    print_structure(export_key,Nh);

    printf("\n    > A 'client_public_key', generated from hkdfExpanded \nunblinded signed hashed password, \
    it's length is 32 bytes:");
    print_structure((uint8_t*) &record.client_public_key,Npk);

    printf("\n    > A 'masking_key', generated from hkdfExpanded \nunblinded signed hashed password, \
    it is used later in Login stage to \nrecover envelope, it's length is 32 bytes:");
    print_structure((uint8_t*) &record.masking_key,Npk);

    printf("\n    > An 'elvelope', structure generated by client and stored on server\n \
    and it includes core params to recover users credentials in login stage.\n"); 

    printf("\n    > An 'envelope' has to params 'nonce' of 32 bytes:");
    print_structure((uint8_t*) &record.envelope.nonce,Nn);
    printf("\n    > And 'auth_tag' of 64 bytes, provides protextion of the envelope:");
    print_structure((uint8_t*) &record.envelope.auth_tag,Nm);


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
    printf("2.) --- LOGIN STAGE --- \n");
    printf("\n2.1) Client generates 'KE1' msg stores 'ClientState':");
    printf("\n    > 'KE1' includes CredentialRequest and AuthRequest structures:");
    printf("\n    >> 'CredentialRequest' holds just blinded_msg (32 bytes):");
    print_structure((uint8_t*) &ke1.credential_request.blinded_message,Noe);
    printf("\n    >> 'AuthRequest' holds client_nonce, client_public_keyshare:");
    printf("\n    >>> 'client_nonce' is just added element of randomness \n \
    and provides forward secrecy (32bytes):");
    print_structure((uint8_t*) &ke1.auth_request.client_nonce,Nn);
    printf("\n    >>> 'client_public_keyshare' is client public key used \n\
    in 3DH during login stage(32bytes):");
    print_structure((uint8_t*) &ke1.auth_request.client_public_keyshare,Npk);

    printf("\n    > 'ClientState' includes password, password_len, blind and ClientAkeState structure");
    printf("\n    >> 'password' (allocated up to 512 bytes):");
    print_structure((uint8_t*) &client_state.password,512);
    printf("\n    >> 'blind' (32 bytes):\n");
    print_structure((uint8_t*) &client_state.blind,512);

    printf("\n    >> 'ClientAkeState' that includes client_secret_key (for 3DH) \n\
    and whole KE1 structure:");
    printf("\n    >>> 'client_secret_key' (32 bytes):");
    print_structure((uint8_t*) &client_state.client_ake_state.client_secret,Nsk);
    printf("\n    >>> 'KE1' (96 bytes):");
    print_structure((uint8_t*) &client_state.client_ake_state.ke1,96);

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

    printf("2.2) Server generates 'KE2' msg stores 'ServerState':");
    printf("\n    > KE2 includes structures CredentialResponse and AuthResponse");
    printf("\n    >> 'AuthResponse' contains server_nonce(rng), server_public_keyshare, server_mac ");
    printf("\n    >>> 'server_nonce' (32bytes) is just added element of \n\
    randomness and provides forward secrecy");
    print_structure((uint8_t*) &ke2.auth_response.server_nonce,Nn);
    printf("\n    >>> 'server_public_keyshare' is server public key used \n\
    in 3DH during login stage(32bytes):");
    print_structure((uint8_t*) &ke2.auth_response.server_public_keyshare,Nn);
    printf("\n    >>> 'server_mac' is hmac used to verify server on \n\
    client-side(32bytes):");
    print_structure((uint8_t*) &ke2.auth_response.server_mac,Nn);

    printf("\n    >> 'CredentialResponse' contains evaluated_message, masking_nonce, masked_response");
    printf("\n    >>> 'evaluated_message' same as in registration stage (32bytes)");
    print_structure((uint8_t*) &ke2.credential_response.evaluated_message,Noe);
    printf("\n    >>> 'masking_nonce' used for credential response pad (32bytes)");
    print_structure((uint8_t*) &ke2.credential_response.masking_nonce,Noe);
    printf("\n    >>> 'masked_response' is essentialy masked envelope and server public key\n\
     with credential response pad  (128bytes):");
    print_structure((uint8_t*) &ke2.credential_response.masked_response,Npk + Nn + Nm);


    printf("\n    > ServerState includes expected_client_mac and session_key");
    printf("\n    >> An 'expected_client_mac' (64 bytes) is precalculated hmac\n\
     that compared with mac from client");
    print_structure((uint8_t*) &server_state.expected_client_mac,Nm);
    printf("\n    >> An 'session_key' (64 bytes) is a shared secret key \n\
    for symmetric encryption of communication:");
    print_structure((uint8_t*) &server_state.session_key,Nx);

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

    printf("2.3) Client generates 'KE3', msg, which is essentially 'client_mac'\n\
     and 'client_session_key':");
    printf("    >> A 'client_mac' (64 bytes) that is being sent to server to comparison:");
    print_structure((uint8_t*) &ke3.client_mac,Nm);
    printf("    >> An 'client_session_key' (64 bytes) is a shared secret \n\
    key for symmetric encryption of communication");
    print_structure(client_session_key,64);

    uint8_t server_session_key[Nx];
    uint8_t r = ServerFinish( // returns 0 if succes, otherwise -1
        server_session_key,
        &server_state, //server state from KE2
        &ke3
    );
    printf("2.4) Server compares 'client_mac' sent in 'KE3', \n\
    to expected_client_mac stored in 'server_state':");
    printf("    >> A 'client_mac' from KE3:");
    print_structure((uint8_t*) &ke3.client_mac,Nh);
    printf("    >> An 'expected_client_mac' stored in ServerState:");
    print_structure((uint8_t*) &server_state.expected_client_mac, Nh);


    if (r == OPAQUE_OK){
        printf("Successfully logged in.\n");
    }
    else {
        printf("Authentification failed with error code:%d !\n", r);
    }
    return 0;
}
