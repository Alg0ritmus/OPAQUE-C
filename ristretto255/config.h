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

/** *****************************************************************
	* This file serves as a configuration file where you can set or
	* unset certain FLAGS based on your preference, enabling or 
	* disabling them as needed. Above each FLAG, you'll find
	* a short description to help you understand its specific
	* purpose. Feel free to experiment with these flags, as
	* you wish.
**/

#ifndef _CONFIG_H
#define _CONFIG_H

/** *****************************************************************
	* We use USE_GF25519SELECT to allow you to choose whether
	* you want to use gf25519Select or gf25519Swap. Both of these
	* functions are declared in the file gf25519.h. Note that originally,
	* CT_SELECT was used in the Ristretto255 draft 
	* (https://datatracker.ietf.org/doc/draft-irtf-cfrg-ristretto255-decaf448/). 
	* However, we decided to primarily use just one function
	* (gf25519Swap). Please note that gf25519Swap is also declared
	* in gf25519.h. Be aware that both of these functions were
	* originally taken and slightly changed from the crypto
	* library Cyclone (https://github.com/Oryx-Embedded/CycloneCRYPTO/blob/master/ecc/curve25519.c).
	*
	* Uncomment if you want to use gf25519Select; otherwise,
	* gf25519Swap will be chosen.
**/

//#define USE_GF25519SELECT


/** *****************************************************************
	*	DEBUG_FLAG enables comments in ristretto255 impl. In other words,
	* when logical codition is not met, enable DEBUG_FLAG flag turns on
	* "error" messages.
	*
	* Uncomment this, if you want to enable error messages.
**/

//#define DEBUG_FLAG 




/** *****************************************************************
	*	Enable VERBOSE_FLAG if you want to enable SUCCESS/FAIL messages
	* during tests (in main.c).
**/
#define VERBOSE_FLAG 




/** *****************************************************************
	* Here, we prepared 2 ways of computing modular inverse (mod L).
	* Using Barrett’s reduction: inverse_mod_l; and Montgomery’s
	* reduction crypto_x25519_inverse. You can choose between these
	* two options by commenting/uncommenting the 
	* MONTGOMERY_MODL_INVERSE_FLAG in config.h. We believe that
	* you should be able to select the implementation that best suits
	* your requirements (based on your benchmark).
	* 
	* "Montgomery’s reduction is not efficient for a single modular
	* multiplication, but can be used effectively in computations
	* where many multiplications are performed for given inputs. 
	* Barrett’s reduction is applicable when many reductions
	* are performed with a single modulus."
	* (https://eprint.iacr.org/2014/040.pdf).
	*
	* Uncomment this flag if you want to use Montgomery’s reduction
	* or comment, if you want to use Barrett’s reduction.
**/
#define MONTGOMERY_MODL_INVERSE_FLAG



/** *****************************************************************
	* We conducted a complex testing of our ristretto255 implementation. 
	* Complex tests are suitable for evaluating every little change,  
	* such as optimization tweaks in the code and more. Through 
	* complex testing, we can identify differences and errors introduced
	* into the codebase, allowing us to eliminate them.

	* By using xxHash, a fast non-cryptographic function, we perform 
	* checksum checks in multiple places during the test, 
	* and at the end of the test the final digest is printed.

	* Here, we can set FLAGS like COMPLEX_TEST_ITERATIONS, 
	* which is the number of rounds for the test, and CNT, 
	* which is an index used to print intermediate digests 
	* (checksums) every CNT rounds.

	* For example, if COMPLEX_TEST_ITERATIONS is set to 10 
	* and CNT is set to 2, the test will run in 10 rounds,
	* and the intermediate checksum will be printed every second round.
**/
#define COMPLEX_TEST_INERATIONS 10
#define CNT 2

#endif // _CONFIG_H
