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

#include <stdio.h>
#include <stddef.h>
#include <string.h> 
#include "dependencies/sha.h"

#include "ristretto255/ristretto255.h"
#include "ristretto255/helpers.h"
#include "ristretto255/utils.h"

#include "oprf.h"
#include "opaque.h"
#include "rnd.h"



/**
  * This file, serves for internal testing purposes.
  *------------------------------------------------
  *
	* SHA512 was tested here:
  * https://emn178.github.io/online-tools/sha512.html
  *
  * HKDF was tested here:
  * https://asecuritysite.com/encryption/hkdf
  *
  * HMAC was tested here:
  * https://www.freeformatter.com/hmac-generator.html#before-output
**/


static void printDigest(uint8_t in[SHA512HashSize]){
	for (int i = 0; i < SHA512HashSize; ++i)
	{
		if (i%16==0){
			printf("\n");
		}
		printf("%0x,",in[i]);
	}
	printf("\n");
}

// int I2OSP(uint64_t x, int xLen, unsigned char *output) {
//     // Step 1: Check if x >= 256^xLen  rethink
//     if (x >= (1ULL << (8 * xLen))) {
//         fprintf(stderr, "Error: Integer (%lli) too large >\n",(x >> 8*xLen));
//         return -1;
//     }

//     // Step 2: Write the integer x in its unique xLen-digit base-256 representation
//     for (int i = xLen - 1; i >= 0; i--) {
//       printf(">%llu\n",x);
//         output[i] = (unsigned char)(x & 0xFF);
//         x >>= 8;
//     }
//     return 1;
// }

int main(){
  srand(1234);

  // -----------------------------------         
  // ------------- TESTING OF ----------
  // -------- SHA512 - HKDF - HMAC -----
  // -----------------------------------   
  #if 0
	uint8_t output[SHA512HashSize];
  uint8_t MYprk[USHAMaxHashSize];

	const uint8_t input[3] = {0x11,0x22,0x33};
  char *input_text = "112233"; // 0x31313232
  uint8_t *input_text_to_hex = (uint8_t *)input_text;
  size_t input_text_length = strlen(input_text);

  const uint8_t salt[3] = {0x44,0x55,0x66};
  char *input_salt = "445566"; // 0x343435353636
  uint8_t *input_salt_to_hex = (uint8_t *)input_salt;
  size_t input_salt_length = strlen(input_salt);

  const uint8_t info[3] = {0x77,0x88,0x99};
  const unsigned char *input_info = "778899"; // 0x373738383939
  uint8_t *input_info_to_hex = (uint8_t *)input_info;
  size_t input_info_length = strlen(input_info);

  // thois is how to work w text
	char *text = "Hello World";
	uint8_t *text_to_hex = (uint8_t *)text;
  size_t text_length = strlen(text);


  const unsigned char *ikm = "Input Key Material";
  size_t ikm_length = strlen(ikm);

  	
	SHA512Context mySha512;

	printf("\nSHA512 hex in test");
	SHA512Reset(&mySha512);
	SHA512Input(&mySha512, input, sizeof(input));
	SHA512Result(&mySha512, output);
	printDigest(output);

	printf("\nSHA512 text in test");
	SHA512Reset(&mySha512);
	SHA512Input(&mySha512, text_to_hex, text_length);
	SHA512Result(&mySha512, output);
	printDigest(output);

	//HKDF extract
	printf("\nHKDF extract test");
	hkdfExtract(SHA512,input_salt,input_salt_length,ikm, ikm_length, MYprk);
	printDigest(MYprk);

	//HKDF expand
  printf("\nHKDF expand test");
  uint8_t okm[SHA512HashSize];
  hkdfExpand(SHA512,MYprk,sizeof(MYprk),input_info, input_info_length, okm, SHA512HashSize);
  printDigest(okm);

  // HMAC-SHA512
  printf("\nHMAC-SHA512 text in test");
  hmac(SHA512, input_text, input_text_length, input_salt,input_salt_length, output);
  printDigest(output);

  #endif // SHA512 - HKDF - HMAC

  // -----------------------------------         
  // ------------- TESTING OF ----------
  // ---------- PKCS #1 - I2OSP --------
  // -----------------------------------  
  #if 0

  uint64_t arr[100] = {1502514348, 2381400790, 1589432030, 285587561, 2154349796, 1443620098, 3378972613, 4160590097, 2200044613, 1764691186, 3637137350, 2002294599, 4124800331, 665880443, 889851675, 3049996475, 3085656286, 1220653718, 3438475557, 2562614526, 4036241375, 3819451420, 2674312900, 998504711, 1845885548, 2866561644, 630446247, 3525990865, 882154773, 3643481399, 3563662923, 3278668065, 2048673300, 2156312426, 1243021298, 553710401, 2657293509, 3739422051, 2486741060, 203339503, 2017841599, 928065142, 2678761907, 2742505196, 2205383338, 3289726211, 3396042652, 1881106393, 1095649096, 2885738315, 4265342897, 88099668, 722367366, 1964369021, 2240267361, 3076499604, 2600632899, 7256782, 2487694571, 1322534064, 96917877, 3987717661, 2663766706, 3794143527, 3525293238, 1007552192, 2261362288, 2756683776, 3617418236, 1242424336, 3227518379, 2752188715, 330074751, 3581270086, 4006250616, 2521753655, 3706150219, 2803248536, 3005225316, 4017975052, 3721236494, 3594668612, 589680989, 1991573957, 3617761718, 760576759, 89986017, 2212251512, 2705537949, 2167823003, 1069152174, 1018200535, 110804191, 3294455507, 1980187717, 792678666, 583020112, 3644820486, 2541073681, 4052429327};
  int xLens[100] = {26, 1, 9, 7, 30, 13, 11, 27, 18, 25, 14, 11, 11, 12, 6, 5, 21, 30, 26, 7, 17, 30, 19, 2, 0, 3, 30, 19, 28, 23, 18, 31, 19, 28, 4, 24, 31, 13, 16, 30, 20, 0, 27, 21, 26, 6, 12, 20, 2, 14, 11, 14, 15, 28, 14, 9, 8, 27, 2, 11, 14, 23, 25, 21, 3, 17, 1, 27, 10, 32, 19, 29, 18, 32, 0, 25, 27, 24, 6, 19, 12, 23, 18, 3, 16, 12, 23, 20, 10, 18, 10, 9, 12, 17, 29, 11, 4, 17, 7, 12};

  for (int i = 0; i < 100; ++i)
  {
    unsigned char octetString[xLens[i]];
    memset(octetString,0,xLens[i]);

    int a = I2OSP(arr[i], xLens[i], octetString);
    if (a)
    {  
      printf("\n");
      printf("Integer: %llu\n", arr[i]);
      printf("Octet String (hex-%d):\n",xLens[i]);
      for (int y = 0; y < xLens[i]; y++) {
          printf("%02X ", octetString[y]);
      }
      printf("\n");
    }
  }
  #endif
  // int xLen = 5;
  // uint64_t arr =  4052429327;
  // unsigned char octetString[xLen];
  // memset(octetString,0,xLen);

  // int a = I2OSP(arr, xLen, octetString);
  // if (a)
  // {  
  //   printf("\n");
  //   printf("Integer: %llu\n", arr);
  //   printf("Octet String (hex-%d):\n",xLen);
  //   for (int y = 0; y < xLen; y++) {
  //       printf("%02X ", octetString[y]);
  //   }
  //   printf("\n");
  // }

  // -----------------------------------         
  // ------------- TESTING OF ----------
  // --------------- OPRF --------------
  // -----------------------------------

  printf("\n---- TESTING BLIND ----\n");
  uint8_t finalizedOutput[64];
  uint8_t blind[32] = {0x64, 0xd3, 0x7a, 0xed, 0x22, 0xa2, 0x7f, 0x51, 0x91, 0xde, 0x1c, 0x1d, 0x69, 0xfa, 0xdb, 0x89, 0x9d, 0x88, 0x62, 0xb5, 0x8e, 0xb4, 0x22, 0x00, 0x29, 0xe0, 0x36, 0xec, 0x4c, 0x1f, 0x67, 0x06}; 
  uint8_t blindedElement[32];
  uint8_t evaluatedElement[32];
  
  #if 1
    uint8_t input[1] = {0x00};
    int inputLen = 1;
  #else
    uint8_t input[17] = {0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a};
    int inputLen = 17;
  #endif
  
  uint8_t testSKS[32] ={0x5e,0xbc,0xea,0x5e,0xe3,0x70,0x23,0xcc,0xb9,0xfc,0x2d,0x20,0x19,0xf9,0xd7,0x73,0x7b,0xe8,0x55,0x91,0xae,0x86,0x52,0xff,0xa9,0xef,0x0f,0x4d,0x37,0x06,0x3b,0x0e};

  ecc_voprf_ristretto255_sha512_BlindWithScalar(blindedElement,input,inputLen,blind);
  printf("\nBlind\n");
  print_32(blind);
  printf("\nBlinded Element\n");
  print_32(blindedElement);

  uint8_t skS[Nsk]; 
  uint8_t pkS[Npk];
  uint8_t seed[Nseed] = {0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3};
  uint8_t _info[8] = {0x74,0x65,0x73,0x74,0x20,0x6b,0x65,0x79};

  printf("\nDeterministicDeriveKeyPair\n");
  DeterministicDeriveKeyPair(skS, pkS, seed, _info, 8);
  printf("keyes:\n");
  printf("skS: ref. 5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e\n");
  print_32(skS);
  printf("pkS\n");
  print_32(pkS);

  printf("\nevaluatedElement\n");
  BlindEvaluate(evaluatedElement,testSKS,blindedElement);
  print_32(evaluatedElement);

  printf("\nFinalized\n");
  Finalize(finalizedOutput, input, inputLen , blind, evaluatedElement);
  printDigest(finalizedOutput);


  printf("\nxmd\n");
  uint8_t xmdDST[38] = {"QUUX-V01-CS02-with-expander-SHA512-256"};
  int lenDST = 38;
  char *xmdMSG = {"abcdef0123456789"};
  int lenMSG = (int)strlen(xmdMSG);
  int in_bytes = 0x20;
  uint8_t xmd[64];
  expand_message_xmd_sha512(xmd, (uint8_t*)xmdMSG, lenMSG, xmdDST, lenDST, in_bytes);

  for (int i = 0; i < in_bytes; ++i)
  {
    printf("%x ", xmd[i]);
  }
  printf("\n");


  // -----------------------------------         
  // ------------- TESTING OF ----------
  // --------------- OPAQUE ------------
  // -----------------------------------   

#if 1
  Envelope envelope;
  uint8_t randomized_password[64] = {0xaa,0xc4,0x8c,0x25,0xab,0x03,0x6e,0x30,0x75,0x08,0x39,0xd3,0x1d,0x6e,0x73,0x00,0x73,0x44,0xcb,0x11,0x55,0x28,0x9f,0xb7,0xd3,0x29,0xbe,0xb9,0x32,0xe9,0xad,0xee,0xa7,0x3d,0x5d,0x5c,0x22,0xa0,0xce,0x19,0x52,0xf8,0xab,0xa6,0xd6,0x60,0x07,0x61,0x5c,0xd1,0x69,0x8d,0x4a,0xc8,0x5e,0xf1,0xfc,0xf1,0x50,0x03,0x1d,0x14,0x35,0xd9};
  int randomized_password_len = 64;
  uint8_t server_public_key[Npk] = {0xb2,0xfe,0x7a,0xf9,0xf4,0x8c,0xc5,0x02,0xd0,0x16,0x72,0x9d,0x2f,0xe2,0x5c,0xdd,0x43,0x3f,0x2c,0x4b,0xc9,0x04,0x66,0x0b,0x2a,0x38,0x2c,0x9b,0x79,0xdf,0x1a,0x78};
  uint8_t server_identity[0] = {};
  int server_identity_len = 0;
  uint8_t client_identity[0] = {};
  int client_identity_len=0;


  uint8_t client_public_key[Npk];
  uint8_t masking_key[Nh];
  uint8_t export_key[Nh];
  Store(
      &envelope, 
      client_public_key,
      masking_key,
      export_key,
      randomized_password, randomized_password_len,
      server_public_key,
      server_identity, server_identity_len,
      client_identity, client_identity_len
      );


  //"envelope": "ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec634b0f5b96109c198a8027da51854c35bee90d1e1c781806d07d49b76de6a28b8d9e9b6c93b9f8b64d16dddd9c5bfb5fea48ee8fd2f75012a8b308605cdd8ba5",
  //"export_key": "1ef15b4fa99e8a852412450ab78713aad30d21fa6966c9b8c9fb3262a970dc62950d4dd4ed62598229b1b72794fc0335199d9f7fcc6eaedde92cc04870e63f16",
  //"client_public_key": "76a845464c68a5d2f7e442436bb1424953b17d3e2e289ccbaccafb57ac5c3675",
  //"masking_key": "1ac5844383c7708077dea41cbefe2fa15724f449e535dd7dd562e66f5ecfb95864eadddec9db5874959905117dad40a4524111849799281fefe3c51fa82785c5",


  print_32(envelope.nonce);
  print_32(envelope.auth_tag);


printf("\n RECOVER!!\n");

  uint8_t client_private_key[Npk];
  CleartextCredentials cleartext_credentials;
  uint8_t export_key_2[Nh];

  Recover(
    client_private_key,
    &cleartext_credentials,
    export_key_2,

    randomized_password, randomized_password_len,
    server_public_key,
    &envelope, 
    server_identity, server_identity_len,
    client_identity, client_identity_len
  );

  printf("client_private_key:\n");
  print_32(client_private_key);

  printf("export_key:\n");
  print_32(export_key_2);

  // "export_key": "1ef15b4fa99e8a852412450ab78713aad30d21fa6966c9b8c9fb3262a970dc62950d4dd4ed62598229b1b72794fc0335199d9f7fcc6eaedde92cc04870e63f16",

  uint8_t oprf_seed[Nh] = {0xf4, 0x33, 0xd0, 0x22, 0x7b, 0x0b, 0x9d, 0xd5, 0x4f, 0x7c, 0x44, 0x22, 0xb6, 0x00, 0xe7, 0x64, 0xe4, 0x7f, 0xb5, 0x03, 0xf1, 0xf9, 0xa0, 0xf0, 0xa4, 0x7c, 0x66, 0x06, 0xb0, 0x54, 0xa7, 0xfd, 0xc6, 0x53, 0x47, 0xf1, 0xa0, 0x8f, 0x27, 0x7e, 0x22, 0x35, 0x8b, 0xba, 0xbe, 0x26, 0xf8, 0x23, 0xfc, 0xa8, 0x2c, 0x78, 0x48, 0xe9, 0xa7, 0x56, 0x61, 0xf4, 0xec, 0x5d, 0x5c, 0x19, 0x89, 0xef};
  uint8_t password[25] = {0x43, 0x6f, 0x72, 0x72, 0x65, 0x63, 0x74, 0x48, 0x6f, 0x72, 0x73, 0x65, 0x42, 0x61, 0x74, 0x74, 0x65, 0x72, 0x79, 0x53, 0x74, 0x61, 0x70, 0x6c, 0x65};
  int password_len = 25;
  uint8_t blind_registration[32] = {0x76, 0xcf, 0xbf, 0xe7, 0x58, 0xdb, 0x88, 0x4b, 0xeb, 0xb3, 0x35, 0x82, 0x33, 0x1b, 0xa9, 0xf1, 0x59, 0x72, 0x0c, 0xa8, 0x78, 0x4a, 0x2a, 0x07, 0x0a, 0x26, 0x5d, 0x9c, 0x2d, 0x6a, 0xbe, 0x01};
  RegistrationRequest request;
  CreateRegistrationRequestWithBlind( 
    blind_registration, 
    &request, 
    password, password_len
  );

  printf("\n CreateRegistrationRequest!!!\n");

  printf("blind:\n");
  print_32(blind_registration);

  printf("request.blinded_message:\n");
  print_32(request.blinded_message);


  printf("CreateRegistrationResponse:\n");

  uint8_t credential_identifier[4] = {0x31, 0x32, 0x33,0x34};
  RegistrationResponse response;
  CreateRegistrationResponse(
    &response,
    &request,
    server_public_key,
    credential_identifier, 4,
    oprf_seed
  );

  printf("\nresponse.evaluated\n");
  print_32(response.evaluated_message);
  #endif


  RegistrationRecord record;
  uint8_t export_key3[Nh];

  FinalizeRegistrationRequest(
   &record,
   export_key3,
   password, password_len,
   blind_registration,
   &response,
   server_identity, server_identity_len,
   client_identity, client_identity_len
  );

  printf("\nexport_key3:\n");
  print_32(export_key3);
  print_32(record.client_public_key);
  print_32(record.masking_key);
  print_32(record.envelope.nonce);
  print_32(record.envelope.auth_tag);

  //////////////////////////
  //  AKE1
  //////

  KE1 ke1;
  ClientState state;
  uint8_t client_nonce[32] = {0xda, 0x7e, 0x07, 0x37, 0x6d, 0x6d, 0x6f, 0x03, 0x4c, 0xfa, 0x9b, 0xb5, 0x37, 0xd1, 0x1b, 0x8c, 0x6b, 0x42, 0x38, 0xc3, 0x34, 0x33, 0x3d, 0x1f, 0x0a, 0xeb, 0xb3, 0x80, 0xca, 0xe6, 0xa6, 0xcc};
  uint8_t blind_login[32] = {0x6e, 0xcc, 0x10, 0x2d, 0x2e, 0x7a, 0x7c, 0xf4, 0x96, 0x17, 0xaa, 0xd7, 0xbb, 0xe1, 0x88, 0x55, 0x67, 0x92, 0xd4, 0xac, 0xd6, 0x0a, 0x1a, 0x8a, 0x8d, 0x2b, 0x65, 0xd4, 0xb0, 0x79, 0x03, 0x08};
  uint8_t client_keyshare_seed[32]=  {0x82, 0x85, 0x0a, 0x69, 0x7b, 0x42, 0xa5, 0x05, 0xf5, 0xb6, 0x8f, 0xcd, 0xaf, 0xce, 0x8c, 0x31, 0xf0, 0xaf, 0x2b, 0x58, 0x1f, 0x06, 0x3c, 0xf1, 0x09, 0x19, 0x33, 0x54, 0x19, 0x36, 0x30, 0x4b};

  printf("\nKE1:\n");
  GenerateKE1(
    &ke1, &state,
    password, password_len,
    blind_login,
    client_nonce,
    client_keyshare_seed
    );

  print_32(ke1.credential_request.blinded_message);
  print_32(ke1.auth_request.client_nonce);
  // 6e29bee50701498605b2c085d7b241ca15ba5c32027dd21ba420b94ce60da326
  print_32(ke1.auth_request.client_public_keyshare);
	


  printf("\nKE2\n");
  KE2 ke2_raw;
  ServerState state_raw;
  uint8_t server_private_key[32] = {0x47, 0x45, 0x1a, 0x85, 0x37, 0x2f, 0x8b, 0x35, 0x37, 0xe2, 0x49, 0xd7, 0xb5, 0x41, 0x88, 0x09, 0x1f, 0xb1, 0x8e, 0xdd, 0xe7, 0x80, 0x94, 0xb4, 0x3e, 0x2b, 0xa4, 0x2b, 0x5e, 0xb8, 0x9f, 0x0d};
  uint8_t context[10] = {0x4f, 0x50, 0x41, 0x51, 0x55, 0x45, 0x2d, 0x50, 0x4f, 0x43};
  uint8_t masking_nonce[32] = {0x38, 0xfe, 0x59, 0xaf, 0x0d, 0xf2, 0xc7, 0x9f, 0x57, 0xb8, 0x78, 0x02, 0x78, 0xf5, 0xae, 0x47, 0x35, 0x5f, 0xe1, 0xf8, 0x17, 0x11, 0x90, 0x41, 0x95, 0x1c, 0x80, 0xf6, 0x12, 0xfd, 0xfc, 0x6d}; 
  uint8_t server_nonce[32] = {0x71, 0xcd, 0x99, 0x60, 0xec, 0xef, 0x2f, 0xe0, 0xd0, 0xf7, 0x49, 0x49, 0x86, 0xfa, 0x3d, 0x8b, 0x2b, 0xb0, 0x19, 0x63, 0x53, 0x7e, 0x60, 0xef, 0xb1, 0x39, 0x81, 0xe1, 0x38, 0xe3, 0xd4, 0xa1};
  uint8_t server_keyshare_seed[32] = {0x05, 0xa4, 0xf5, 0x42, 0x06, 0xee, 0xf1, 0xba, 0x2f, 0x61, 0x5b, 0xc0, 0xaa, 0x28, 0x5c, 0xb2, 0x2f, 0x26, 0xd1, 0x15, 0x3b, 0x5b, 0x40, 0xa1, 0xe8, 0x5f, 0xf8, 0x0d, 0xa1, 0x2f, 0x98, 0x2f};
  
  ecc_opaque_ristretto255_sha512_GenerateKE2WithSeed(
    &ke2_raw,
    &state_raw,
    server_identity, server_identity_len,
    server_private_key,
    server_public_key,
    &record,
    credential_identifier, 4,
    oprf_seed,
    &ke1,
    client_identity, client_identity_len,
    context, 10,
    masking_nonce,
    server_nonce,
    server_keyshare_seed
  );

  // 7e308140890bcde30cbcea28b01ea1ecfbd077cff62c4def8efa075aabcbb471
  printf("KE2 credential_response evaluated_message:\n");
  print_32(ke2_raw.credential_response.evaluated_message);

  // 38fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d
  printf("KE2 credential_response masking_nonce:\n");
  print_32(ke2_raw.credential_response.masking_nonce);

  // d6ec60bcdb26dc455ddf3e718f1020490c192d70dfc7e403981179d8073d1146a4f9aa1ced4e4cd984c657eb3b54ced3848326f70331953d91b02535af44d9fedc80188ca46743c52786e0382f95ad85c08f6afcd1ccfbff95e2bdeb015b166c6b20b92f832cc6df01e0b86a7efd92c1c804ff865781fa93f2f20b446c8371b6
  printf("KE2 credential_response masked_response:\n");
  print_32(ke2_raw.credential_response.masked_response);


  // 71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1
  printf("KE2 auth_response server_nonce:\n");
  print_32(ke2_raw.auth_response.server_nonce);

  // c4f62198a9d6fa9170c42c3c71f1971b29eb1d5d0bd733e40816c91f7912cc4a
  printf("KE2 auth_response server_public_keyshare:\n");
  print_32(ke2_raw.auth_response.server_public_keyshare);

  // 660c48dae03e57aaa38f3d0cffcfc21852ebc8b405d15bd6744945ba1a93438a162b6111699d98a16bb55b7bdddfe0fc5608b23da246e7bd73b47369169c5c90
  printf("KE2 auth_response server_mac:\n");
  print_32(ke2_raw.auth_response.server_mac);




  printf("\n GenerateKE3\n");

  KE3 ke3_raw;
  uint8_t client_session_key[64];
  uint8_t export_key4[64];
  ecc_opaque_ristretto255_sha512_GenerateKE3(
    &ke3_raw,
    client_session_key,
    export_key4, // 64
    &state, // from KE1
    client_identity, client_identity_len,
    server_identity, server_identity_len,
    &ke2_raw, // from ke2_raw
    context, 10
  );

  printf("KE3 client_mac:\n");
  print_32(ke3_raw.client_mac);
  printf("client_session_key\n");
  print_32(client_session_key);
  printf("export_key4\n");
  print_32(export_key4);


  printf("ServerFinish\n");
  uint8_t session_key[Nx];
  ecc_opaque_ristretto255_sha512_ServerFinish(
    session_key,
    &state_raw, //server state from KE2
    &ke3_raw
  );

  printf("ServerFinish, session_key\n");
  print_32(session_key);
  print_32(&session_key[32]);



  return 0;

}



