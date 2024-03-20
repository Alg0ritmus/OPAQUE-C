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


/**
  * This file contains some useful functions for printing, eq.
**/

// Dependencies
#include "utils.h"

void print(const field_elem o){

    for (int i=0;i<FIELED_ELEM_SIZE;i++){
        printf("%x ", (int) o[i]);            
        
    }
    printf("\n");
}


void print_32(const u8* o){

    for (int i=0;i<BYTES_ELEM_SIZE;i++){
        printf("%02hx ", o[i]);
        
    }
    printf("\n");
}

// return 0 if they're equal
// checking if two u8[32] are eq
bool bytes_eq_32( const u8 a[BYTES_ELEM_SIZE],  const u8 b[BYTES_ELEM_SIZE]){
    bool result = false;

    for (int i = 0; i < BYTES_ELEM_SIZE; ++i){
        result |= a[i] != b[i];
    }

    return result;
}

void crypto_wipe(void *secret, int32_t size)
{
    volatile u8 *v_secret = (u8*)secret;
    int32_t idx;
    ZERO(idx, v_secret, size);
}