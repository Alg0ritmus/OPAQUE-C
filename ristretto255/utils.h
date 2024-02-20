// ******************************************************************
// ----------------- TECHNICAL UNIVERSITY OF KOSICE -----------------
// ---Department of Electronics and Multimedia Telecommunications ---
// -------- FACULTY OF ELECTRICAL ENGINEERING AND INFORMATICS -------
// ------------ THIS CODE IS A PART OF A MASTER'S THESIS ------------
// ------------------------- Master thesis --------------------------
// -----------------Patrik Zelenak & Milos Drutarovsky --------------
// ---------------------------version T.T.5 -------------------------
// --------------------------- 10-02-2024 ---------------------------
// ******************************************************************

/**
  * This file contains some useful functions for printing, eq. 
**/

#ifndef _UTILS_H
#define _UTILS_H

#include "helpers.h"

/*      UTILS       */
void print(const field_elem o);

void print_32(const u8* o);

int bytes_eq_32( const u8 a[BYTES_ELEM_SIZE],  const u8 b[BYTES_ELEM_SIZE]);

void crypto_wipe(void *secret, size_t size);


// The macro WIPE_BUFFER is used throughout this file,
// and it employs the crypto_wipe function (defined in utils.c)
// to securely erase input data.
#define WIPE_BUFFER(buffer)        crypto_wipe(buffer, sizeof(buffer))

/**
  * In the context of a crypto library, using volatile to prevent the
  * compiler from optimizing out memory zeroing is a safety 
  * precaution. Crypto libraries often deal with sensitive data,
  * and ensuring that memory is securely wiped (zeroed) is a critical
  * security requirement to prevent data leakage.
  *
  * The compiler's optimization may decide to skip the zeroing
  * operation if it believes the memory is never read afterward.
  * By using volatile, you're essentially telling the compiler
  * not to make that assumption and to perform the zeroing operation
  * regardless of whether the memory is explicitly read afterward.
  * This helps ensure that sensitive data is properly wiped from 
  * memory, which is crucial for security purposes.
  *
  * In other words, we need to use volatile because the compiler
  * might skip zeroing the buffer due to optimization and make the
  * assumption that 'why would I write into the buffer when it
  * is never read.'
  *
  * One more comment on volatile keyword:
  * The 'volatile' keyword is used to indicate to the compiler that
  * a variable or object can change its value at any time without any
  * action being taken by the code the compiler finds nearby. 
  * This is typically used to prevent the compiler from optimizing
  * away certain accesses to memory, especially in cases where 
  * the memory might be modified by hardware, another thread,
  * or some other external entity that the compiler cannot predict.
  *
  * Last but not least, the difference between volatile on a pointer
  * and volatile on a variable is that volatile on a pointer indicates
  * that the data being pointed to may change,
  * while volatile on a variable indicates that the variable itself
  * may change at any time.
  *
  * Note:
  * A pointer of the form volatile volatile u8 *v_secret
  * is a pointer to an u8 that the compiler will treat as volatile.
  * This means that the compiler will assume that it is possible
  * for the variable that v_secret is pointing at to have changed
  * even if there is nothing in the source code to suggest that
  * this might occur. (https://stackoverflow.com/questions/9935190/why-is-a-point-to-volatile-pointer-like-volatile-int-p-useful).
**/


/*-----------------------------------*/
#endif //_UTILS_H

