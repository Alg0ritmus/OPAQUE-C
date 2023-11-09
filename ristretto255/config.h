// ******************************************************************
// ----------------- TECHNICAL UNIVERSITY OF KOSICE -----------------
// ---Department of Electronics and Multimedia Telecommunications ---
// -------- FACULTY OF ELECTRICAL ENGINEERING AND INFORMATICS -------
// ------------ THIS CODE IS A PART OF A MASTER'S THESIS ------------
// ------------------------- Master thesis --------------------------
// -----------------Patrik Zelenak & Milos Drutarovsky --------------
// ---------------------------version 0.1.3 -------------------------
// --------------------------- 30-09-2023 ---------------------------
// ******************************************************************

/** *****************************************************************
	* This file serves as a configuration file where you can set or
	* unset certain FLAGS based on your preference, enabling or 
	* disabling them as needed. Above each FLAG, you'll find
	* a short description to help you understand its specific
	* purpose. Feel free to experiment with these flags, but
	* please note that even if BIGENDIAN_FLAG is present,
	* we do not recommend using it because it is very likely
	* not working properly YET.
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
	* Choose between Little/Big endian with this flag. Be highly
	* aware that, for now, this flag is not well-tested, and we
	* do not recommend enabling it (uncommenting it). So far, our
	* implementation is not fully suitable for Big Endian systems.
	*
	* Uncomment if you want to use Big Endian implementation
	* of our ristretto255 impl. Be aware that our impl. is not
	* well-tested (probably not fully functioning) on Big Endian
	* architectures.
**/
//#define BIGENDIAN_FLAG 




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
//#define MONTGOMERY_MODL_INVERSE_FLAG


#endif // _CONFIG_H
