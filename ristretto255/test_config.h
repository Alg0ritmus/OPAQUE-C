// ******************************************************************
// ----------------- TECHNICAL UNIVERSITY OF KOSICE -----------------
// ---Department of Electronics and Multimedia Telecommunications ---
// -------- FACULTY OF ELECTRICAL ENGINEERING AND INFORMATICS -------
// ------------ THIS CODE IS A PART OF A MASTER'S THESIS ------------
// ------------------------- Master thesis --------------------------
// -----------------Patrik Zelenak & Milos Drutarovsky --------------
// ---------------------------version T.T.5 -------------------------
// --------------------------- 05-02-2024 ---------------------------
// ******************************************************************


/** *****************************************************************
	* This file serves as a configuration file, where you can
	* set various input variables when running tests from
	* main.c file. Feel free to experiment with this variables.
**/

#ifndef _TEST_CONFIG_H
#define _TEST_CONFIG_H
#include "helpers.h"

// TEST MODULO L (modl_l_inverse)

  /** DESCRIPTION: 
    * In main.c, we implemented test for our mod. inv function
    * modl_l_inverse, line 312. Here is brief description.
    * iner[32] is input/output variable used in our test of
    * function modl_l_inverse. Firstly it is filled with 0xff
    * (every element of u8[32] array is filled with 0xff).
    * Then we use it as input parameter into modl_l_inverse.
    * At the end of the test, we also write output into Iner[32]
    * variable.
    * Here r[32] is temporary variable used for intermediate
    * calculation in modl_l_inverse test. Note that our test of 
    * modl_l_inverse is performed as follow:
    * 1)Perform tasks below 'rounds' times:
    * 1.1) perform; r := mod_L_inverse(iner)
    * 1.2) perform 'masking' with xor; iner := r XOR testing_constant
    * Note that testing constat is set to 0x57, feel free to chage it
    * but dont forget to change modL_test_vec vector,
    * which is eventually used in comparison iner==modL_test_vec.
    * You can use python script that we used to generate test vector.
    * Python script is named "py_modl_l_inverse.py" and you can
    * executed it from command line by using one of three commands:
    * "py py_modl_l_inverse.py"
    * "python py_modl_l_inverse.py"
    * "python3 py_modl_l_inverse.py"
    * Feel free to change these variables, and compare results
    * with Python impl., but please dont forget to change variable
    * also in python script accordingly.
  **/

    /* VECTORS MODULO L */
	// Here r[32] is temporary variable used for intermediate
    // calculation in modl_l_inverse test.
    u8 r[32];

    // iner[32] is input/output variable used in our test of
    // function modl_l_inverse.
    u8 iner[32] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};

    // testing_constant is used in 'masking' part of modl_l_inverse
    // test, see in description above.
    const u8 testing_constant = 0x57;

    // modL_test_vec is test vector to which we compare result 
    // of modl_l_inverse test. Note that if you change variable 
    // 'rounds' or 'testing_constant' you need to change also
    // test vector. You can do it simply by generating test
    // vector using python sctipt 'py_modl_l_inverse.py'.
    // But please, change variables in python script so they
    // match with variables defined in this file section.
    const u8 modL_test_vec[32] = {0x9,0x78,0xd0,0xfb,0xe4,0x4d,0x7c,0x69,0x60,0xa9,0xab,0x59,0xf3,0xad,0x3c,0x13,0xd8,0x9b,0xd1,0xe6,0x11,0x2a,0x65,0xeb,0x48,0xc9,0x9d,0x7a,0x18,0x40,0x88,0x5f};

    // rounds sets amount of for-loop cycles
    const int rounds = 1000;
	/* END VECTORS MODULO L */


#endif //_TEST_CONFIG_H