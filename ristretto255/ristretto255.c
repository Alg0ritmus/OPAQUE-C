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

/**
  * This file is core of our ristretto255 implementation. It is more
  * efficient version of our equivalent TweetNaCl version 
  * of ristretto255 (https://github.com/Alg0ritmus/textbook_ristretto255).
  * This file includes all necessary functions for creation of other
  * protocols that use  eliptic curve Curve25519. 
  *
  * Ristretto255 is a cryptographic construction designed for 
  * efficient and secure elliptic curve cryptography (ECC) 
  * operations. It is based on the Curve25519 elliptic curve,
  * which is a widely used curve in modern cryptography
  * due to its strong security properties and efficient performance.
  *
  * Curve25519, the underlying elliptic curve, has a cofactor of 8,
  * meaning its order is eight times a prime number. This cofactor 
  * introduces the possibility of small subgroup attacks because not
  * all points on the curve are in the main subgroup. The cofactor
  * is a factor by which the order of the elliptic curve group is
  * divisible. In elliptic curve cryptography, it's important to work
  * with points that are on the main subgroup of the curve, as points
  * on small subgroups can introduce vulnerabilities.
  *
  * Ristretto255 addresses this issue by providing a way to map 
  * points from the Curve25519 curve to a unique representative point
  * in a group that eliminates the cofactor-related vulnerabilities.
  * By doing so, it ensures that all points in its representation 
  * belong to the main subgroup, making it resistant to small 
  * subgroup attacks and other potential security issues associated
  * with the cofactor. This mapping is carefully designed to maintain
  * compatibility with Curve25519's arithmetic operations while 
  * addressing the cofactor problem, thus providing a safer
  * and more predictable foundation for cryptographic protocols.
  *
  * In our representation we used Cyclone, a crypto library,
  * that internaly works with 8-word elements. This is why we chose
  * field_elem (our internal representation of GF(2*255-19) 
  * field element) as 8-word elements. We chose Cyclone crypto library
  * because of its advantages, such as compactness and speed,
  * elimination of I/O conversion. In other words, we do not need to
  * perform any conversion, such as pack/unpack or from_bytes/to_bytes
  * as required by other libraries like TweetNaCl or MonoCypher. Note
  * that we are using pack/unpack terminology just for copying data.
  * Most of the functions used from Cyclone are identical with 
  * original code. In fact we just extract and rename all necessary
  * functions.
  *
  * Results from our speed measurements have shown that Cyclone is
  * approximately 5 times faster than TweetNaCl (packing/unpacking
  * not included). Additionally, while MonoCypher is slightly faster
  * (about 1.5 times) than Cyclone, there are highly efficient 
  * implementations written in assembly language that outperform
  * any C implementations. These are particularly suitable for
  * embedded MCUs like the ARM Cortex-M4. This is one of the reasons
  * why we chose Cyclone.
  * Note that measurements were performed on an STM32 MCU with
  * a Cortex-M3 core. 
  * 
  * Besides Cyclone we also implemented necessary functions to 
  * perform scalar multiplication of ristretto255 point.
  * Ristretto255 point has its own representation (see `helpers.h`),
  * that uses extended Edwards point form. Internally, a Ristretto
  * point is represented by an extended Edwards point. 
  * Two extended Edwards points P,Q may represent the same Ristretto
  * point, in the same way that different projective X,Y,Z,T 
  * coordinates may represent the same extended Edwards point.
  * Group operations on Ristretto points are carried out with no 
  * overhead by performing the operations on the representative
  * Edwards points. For example ristretto255_point_addition() performs
  * addition of ristretto255 points, which impl. was largely inspired
  * by TweetNaCl crypto library.
  *
  * Note that we added STACK SIZE/DEPTH, which shows you 
  * approximately how many bytes you need to allocate on
  * the stack for each function. Take this information
  * as an approximation.
**/

#include <string.h>
#include "ristretto255.h"
#include "ristretto255_constants.h"
#include "gf25519.h"
#include "modl.h"

// Note that macro WIPE_PT uses macro WIPE_BUFFER to wipe 
// ristretto255_point which structure is declared in helpers.h
// Macro WIPE_BUFFER uses crypto_wipe function implemented also 
// in helpers.h. It is wiping function that makes sure we clear memory 
// respomsibly. Function was taken from Monocypher crypto library.
// For more information see helper.h.
#define WIPE_PT(rpoint) wipe_ristretto255_point(rpoint)
// functions redefined below are "renamed" to fit our equivalent 
// TweetNaCl representation of ristretto255
#define swap25519 gf25519Swap     // 8B
#define fsub gf25519Sub           // 60B + 3size_t 
#define fadd gf25519Add           // 60B + 3size_t 
#define fmul gf25519Mul           // 132B+ 4size_t
#define pow2 gf25519Sqr           // 132B + 4size_t
#define pow_xtimes gf25519Pwr2    // 132B + 5size_t
#define feq !gf25519Comp          // 4B + size_t
#define carry25519(out, in) gf25519Red(out, in) //  52B + 2size_t 
#define b_copy gf25519Copy        // size_t
#define fcopy gf25519Copy         // size_t

#ifdef USE_GF25519SELECT
#define fselect gf25519Select     // 4B + size_t
#endif

// Setting "order" during pack/unpack w respect to BIGENDIAN_FLAG
// Note that we are using pack/unpack terminology just for copying data.
// See our TweetNaCl implementation (https://github.com/Alg0ritmus/textbook_ristretto255),
// where packing/unpacking takes big role.
#ifdef BIGENDIAN_FLAG
// Note: We could use pack impl. written below, but we chose store32_le_buf
// function that has the same effect -> convert u32 array into u8 array
// store32_le_buf() implementation can be found in modl.c
#define unpack(uint32Array, uint8Array) store32_le_buf(uint32Array, uint8Array,8)

// void pack(u8* uint8Array,const u32* uint32Array) {
//     for (int i = 0; i < 8; ++i) {
//         uint8Array[i * 4 + 3] = ((uint32Array[i] >> 0) & 0xFF);
//         uint8Array[i * 4 + 2] = ((uint32Array[i] >> 8) & 0xFF);
//         uint8Array[i * 4 + 1] = ((uint32Array[i] >> 16) & 0xFF);
//         uint8Array[i * 4 + 0] = ((uint32Array[i] >> 24) & 0xFF);
//     }
// }

void unpack(u32* uint32Array, const u8* uint8Array) {
    for (int i = 0; i < 8; ++i) {
        uint32Array[i] = (uint8Array[i * 4 + 3] << 0) |
                         (uint8Array[i * 4 + 2] << 8) |
                         (uint8Array[i * 4 + 1] << 16)|
                          uint8Array[i * 4 + 0] << 24;
    }
}
#else
void pack(u8* uint8Array,const u32* uint32Array) { 
  memcpy(uint8Array, (u8*) uint32Array, 32);
}

void unpack(u32* uint32Array, const u8* uint8Array) {
  memcpy(uint32Array, uint8Array, 32);
}

#endif //BIGENDIAN_FLAG

// Wiping ristretto255 point, using WIPE macro
// Note that macro WIPE uses wipe_field_elem() function
// implemented in utils.c
static void wipe_ristretto255_point(ristretto255_point* ristretto_in){
  WIPE_BUFFER(ristretto_in->x);
  WIPE_BUFFER(ristretto_in->y);
  WIPE_BUFFER(ristretto_in->z);
  WIPE_BUFFER(ristretto_in->t);

}


#define pack25519 pack
#define unpack25519 unpack

/**
  * @brief Negation of field_elem
  * @param[in]   -> in
  * @param[out]  -> -in
**/
// fneg() => creates negative input and "save" it to variable out
// function uses modular logic where negation of element a -> p-a = -a 
// inspired by: https://github.com/jedisct1/libsodium/blob/master/src/libsodium/include/sodium/private/ed25519_ref10_fe_51.h#L94
// *** STACKSIZE: u8[32] = 60B + 3size_t  ***
void fneg(field_elem out, field_elem in){
    fsub(out, F_MODULUS, in);

};


/**
  * @brief Returns 1 if field_elem is negative 
  * @param[in]   -> in
  * @param[out]  -> Boolean: True/False
**/
// Note that field_elem is negative, only if LSB is set to 1,
// otherwise it is  positive
// This is something that is very important to realize,
// when constructing ristretto255 bcs.
// it is used on multiple places in code
// inspired by: https://github.com/jedisct1/libsodium/blob/master/src/libsodium/include/sodium/private/ed25519_ref10_fe_25_5.h#L302
// *** STACKSIZE: u8[32] = 32B ***
int is_neg(field_elem in){
    u8 temp[BYTES_ELEM_SIZE];
    pack25519(temp, in);
    return temp[0] & 1;
}


/**
  * @brief Returns 1 if u8[BYTES_ELEM_SIZE] is negative 
  * @param[in]   -> in
  * @param[out]  -> Boolean: True/False
**/
// equivalent for is_neg for 32-word u8[32] element
int is_neg_bytes(const u8 in[BYTES_ELEM_SIZE]){
    return in[0] & 1;
}

/**
  * @brief Returns absolute value of field_elem
  * @param[in]   -> in
  * @param[out]  -> abs(in)
**/
// fabsolute functions gets absolute value of input in constant time 
// *** STACKSIZE: 1x field_elem = 92B + 3size_t  ***
void fabsolute(field_elem out, field_elem in){
    field_elem temp;
    fcopy(temp,in); // temp=in, so I dont rewrite in
    fneg(out,temp); // out = ~in
    // CT_SWAP if it is neg.
    swap25519(out,temp,is_neg(in));

    WIPE_BUFFER(temp);
}


/**
  * @brief Returns 1 if nonnegative root exists
  * @param[in]   -> a
  * @param[in]   -> b
  * @param[out]  -> nonnegative square root of either (a/b)^1/2 or (ia/b)^1/2
**/
// function that calc ristretto255 inverse square root
// Implementing Ristretto requires computing (inverse) square roots.
// Ed25519 implementations compute square roots as part of the
// Ed25519 decompression functionality,
// but this is often inlined into the decompression formulas,
/// so we need to tune existing Cyclone's curve25519Sqrt
// to fit our needs. Note that our inv_sqrt() computes the
// nonnegative square root of either (a/b)^1/2 or (ia/b)^1/2,
// where i = SQRT_M1 (constant from ristretto255 draft).
// Internal compotation of inversion of B and the square root:
// A * B^3 * (A * B^7)^((p - 5) / 8)
// largely inspired by Cyclone's curve25519Sqrt:
// https://github.com/Oryx-Embedded/CycloneCRYPTO/blob/master/ecc/curve25519.c#L430
// Logic Inspired by: https://ristretto.group/formulas/invsqrt.html
// *** STACKSIZE: 196B + 5size_t ***
static int inv_sqrt(field_elem out,const field_elem a, const field_elem b){
   int correct_sign_sqrt;
   int flipped_sign_sqrt;
   int flipped_sign_sqrt_i;
   field_elem c; field_elem v;

   // Compute the candidate root (A / B)^((p + 3) / 8). This can be
   // done with the following trick, using a single modular powering 
   // for both the inversion of B and the square root:
   // A * B^3 * (A * B^7)^((p - 5) / 8)
   pow2(v, b);
   fmul(v, v, b);
   pow2(v, v);
   fmul(v, v, b);

   //Compute C = A * B^7
   fmul(c, a, v);

   //Compute U = C^((p - 5) / 8)
   pow2(out, c);
   fmul(out, out, c);                     //C^(2^2 - 1)
   pow2(out, out);
   fmul(v, out, c);                       //C^(2^3 - 1)
   pow_xtimes(out, v, 3);
   fmul(out, out, v);                     //C^(2^6 - 1)
   pow2(out, out);
   fmul(v, out, c);                       //C^(2^7 - 1)
   pow_xtimes(out, v, 7);
   fmul(out, out, v);                     //C^(2^14 - 1)
   pow2(out, out);
   fmul(v, out, c);                       //C^(2^15 - 1)
   pow_xtimes(out, v, 15);
   fmul(out, out, v);                     //C^(2^30 - 1)
   pow2(out, out);
   fmul(v, out, c);                       //C^(2^31 - 1)
   pow_xtimes(out, v, 31);
   fmul(v, out, v);                       //C^(2^62 - 1)
   pow_xtimes(out, v, 62);
   fmul(out, out, v);                     //C^(2^124 - 1)
   pow2(out, out);
   fmul(v, out, c);                       //C^(2^125 - 1)
   pow_xtimes(out, v, 125);
   fmul(out, out, v);                     //C^(2^250 - 1)
   pow2(out, out);
   pow2(out, out);
   fmul(out, out, c);                     //C^(2^252 - 3)


   //The first candidate root is U = A * B^3 * (A * B^7)^((p - 5) / 8) 
   fmul(out, out, a);
   pow2(v, b);
   fmul(v, v, b);
   fmul(out, out, v);

   //Calculate C = B * U^2 // CHECK
   pow2(c, out);
   fmul(c, c, b);

   //Conditions:
   correct_sign_sqrt = feq(c, a);

   fneg(v,(uint32_t *)a);
   flipped_sign_sqrt = feq(c, v);


   fmul(v, v, SQRT_M1);
   flipped_sign_sqrt_i = feq(c, v);

   //Calc v = i*r
   fmul(v, SQRT_M1, out);
   /**
     * Note we can select between swap25519 and fselect functions.
     * We prefer (default) to use swap25519, bcs. less code is needed.
     * Feel free to change it as u need in config.h
     * if cond = 1, select first option fselect and swap25519
   **/
   #ifdef USE_GF25519SELECT
   fselect(out, out, v, flipped_sign_sqrt | flipped_sign_sqrt_i ); 
   #else
   swap25519(out, v, flipped_sign_sqrt | flipped_sign_sqrt_i ); 
   #endif

  // calc v = -r
   fneg(v,out);
   // if cond = 1, select first option
   #ifdef USE_GF25519SELECT
   fselect(out, out, v, is_neg(out)); 
   #else
   swap25519(out, v, is_neg(out)); 
   #endif  

   WIPE_BUFFER(c); WIPE_BUFFER(v);
   return correct_sign_sqrt | flipped_sign_sqrt;
}


/**
  * @brief Maps field_elem into ristretto255_point
  * @param[in]   -> t
  * @param[out]  -> ristretto255_point from field_elem
**/
// MAP function from draft
// MAP is used in hash_to_group() fuction to get ristretto point
// from hash
// Input parameter is field_elem "t"
// Output is point on Edward's (interpreted as ristretto255_point)
// curve with coords X,Y,Z,T
// MAP is also called ristretto255_elligator

// Note that we redefined temporary variables multiple times
// just to make code more readible. We also added comments
// at the end of the lines, so you will be able to compare
// every line with draft specification.
// DRAFT from 2023-09-18:
// https://datatracker.ietf.org/doc/draft-irtf-cfrg-ristretto255-decaf448/
// *** STACKSIZE: 356B + 5size_t + 2x int ***
static void MAP(ristretto255_point* ristretto_out, const field_elem t){ 
    field_elem tmp1, tmp2, tmp3, tmp4, tmp5;
    int was_square, wasnt_square;

    // TODO: dopln 
    #define _r tmp1
    #define out tmp2
    #define c tmp3
    #define rpd tmp4
    #define v tmp5
    fmul(_r,t,t);                         // r =t^2

    fmul(_r,SQRT_M1,_r);                  // r = SQRT_M1 * t^2
    fadd(out,_r,F_ONE);                   // r + 1

    fmul(out,out,ONE_MINUS_D_SQ);         // u  = (r + 1) * ONE_MINUS_D_SQ
    fneg(c,(uint32_t *)F_ONE);            // -1

    fadd(rpd,_r,EDWARDS_D);               // r+D 
    fmul(v,_r,EDWARDS_D);                 // r*D
    fsub(v,c,v);                          // -1 -r*D
    fmul(v,v,rpd);                        // v = (-1 - r*D) * (r + D)
    
    #define s tmp4
    #define s_prime tmp2
    was_square = inv_sqrt(s,out,v);       //(was_square, s) = SQRT_RATIO_M1(u, v)

    // note: we used swap25519 instead of fselect so our logic
    // is little bit different here
    wasnt_square = 1 - was_square;     

    fmul(s_prime,s,t);                    // s*t
    fabsolute(s_prime,s_prime);           // CT_ABS(s*t)
    fneg(s_prime,s_prime);                // -CT_ABS(s*t)

    swap25519(s,s_prime,wasnt_square);    // s = CT_SELECT(s IF was_square ELSE s_prime)
    #define rc tmp2
    fcopy(rc,_r);
    swap25519(c,rc,wasnt_square);         // c = CT_SELECT(-1 IF was_square ELSE r)

    #define n tmp2
    fsub(n,_r,F_ONE);                     // r-1
    fmul(n,n,c);                          // c*(r-1)
    fmul(n,n,D_MINUS_ONE_SQ);             // c * (r - 1) * D_MINUS_ONE_SQ
    fsub(n,n,v);                          // N = c * (r - 1) * D_MINUS_ONE_SQ - v

    #define ss tmp1
    #define w0 tmp3
    fmul(ss,s,s);                         // s^2

    fadd(w0,s,s);
    fmul(w0,w0,v);                        // w0 = 2 * s * v
    #define w1 tmp4
    fmul(w1,n,SQRT_AD_MINUS_ONE);         // w1 = N * SQRT_AD_MINUS_ONE
    #define w2 tmp2
    #define w3 tmp5
    fsub(w2,F_ONE,ss);                    // w2 = 1 - s^2
    fadd(w3,F_ONE,ss);                    // w3 = 1 + s^2

    fmul(ristretto_out->x,w0,w3);         // w0*w3
    fmul(ristretto_out->y,w2,w1);         // w2*w1         
    fmul(ristretto_out->z,w1,w3);         // w1*w3 
    fmul(ristretto_out->t,w0,w2);         // w0*w2

    WIPE_BUFFER(ss); WIPE_BUFFER(w2); WIPE_BUFFER(w0);
    WIPE_BUFFER(w1); WIPE_BUFFER(w3);
}



/**
  * @brief Add two ristretto255_point points
  * @param[in]   -> p ristretto255_point
  * @param[in]   -> q ristretto255_point
  * @param[out]  -> r ristretto255_point
**/
// Ristretto255 point addition (Edward's coords | X,Y,Z,T ) 
// ristretto255_point_addition is identical to 
// tweetNaCl sv add(gf p[4],gf q[4]),
// Basically I changed name to smth more slef-explaining and 
// changed gf[4] to our ristretto255_point representation
// of ristretto points. NOTE: gf is the same as our field_elem
// (just naming is different)
// https://github.com/dominictarr/tweetnacl/blob/master/tweetnacl.c#L590

// Note that we redefined temporary variables multiple times
// just to make code more readible.
// *** STACKSIZE: 292B+ 4size_t ***
void ristretto255_point_addition(ristretto255_point* r,const ristretto255_point* p,const ristretto255_point* q){
    field_elem temp_1,temp_2,temp_3, temp_4, temp_5;

    #define a temp_1
    #define _t temp_2
    #define b temp_3
    
    fsub(a, p->y, p->x);
    fsub(_t, q->y, q->x);
    fmul(a, a, _t);
    fadd(b, p->x, p->y);
    fadd(_t, q->x, q->y);
    fmul(b, b, _t);

    #define e temp_5
    #define h temp_2
    fadd(h, b, a);
    fsub(e, b, a);
    
    
    #define d temp_1
    #define _c temp_3
    fmul(d, p->z, q->z);
    fadd(d, d, d);

    fmul(_c, p->t, q->t);
    fmul(_c, _c, EDWARDS_D2);
    #define f temp_4
    fsub(f, d, _c);
    #define g temp_3
    fadd(g, d, _c);

    fmul(r->x, e, f);
    fmul(r->y, h, g);
    fmul(r->z, g, f);
    fmul(r->t, e, h);

    WIPE_BUFFER(d); WIPE_BUFFER(h); WIPE_BUFFER(g);
    WIPE_BUFFER(f); WIPE_BUFFER(e);
}


/**
  * @brief Conditional swap if b is set to 1
  * @param[in/out]   -> p ristretto255_point
  * @param[in/out]   -> q ristretto255_point
  * @param[in]       -> b if set to 1 swap
**/
// cswap() => conditional swap, if b is set to 1,
// then swap 2 ristretto points
// inspired by tweetNaCl: https://github.com/dominictarr/tweetnacl/blob/master/tweetnacl.c#L615
// *** STACKSIZE: 8B ***
static void cswap(ristretto255_point* p, ristretto255_point* q,u8 b){
    swap25519(p->x,q->x,b);
    swap25519(p->y,q->y,b);
    swap25519(p->z,q->z,b);
    swap25519(p->t,q->t,b);
}



/**
  * @brief Decode input bytes u8[32] to ristretto255_point
  * @param[in]   -> bytes_in[32]
  * @param[out]   -> ristretto_out ristretto255_point
**/
// Inspired by ristretto draft
// generate ristretto point from bytes[32]

// Note that we redefined temporary variables multiple times
// just to make code more readible. We also added comments
// at the end of the lines, so you will be able to compare
// every line with draft specification.
// DRAFT from 2023-09-18:
// https://datatracker.ietf.org/doc/draft-irtf-cfrg-ristretto255-decaf448/
// *** STACKSIZE: 420B + 5size_t + 3int ***
int ristretto255_decode(ristretto255_point *ristretto_out, const u8 bytes_in[BYTES_ELEM_SIZE]){
  
  int was_square, is_canonical, is_negative;

  field_elem temp1,temp2,temp3,temp4,temp5,temp6;

  u8 checked_bytes[BYTES_ELEM_SIZE];

  // Step 1: Check that the encoding of the 
  // field element is canonical
  #define _s temp1
  unpack25519(_s, bytes_in);
  pack25519(checked_bytes,_s);

  

  // check if bytes_in == checked_bytes, else abort
  is_canonical = bytes_eq_32(checked_bytes,bytes_in);
  is_negative = is_neg_bytes(bytes_in);

  if (is_canonical == 0 || is_negative==1){
    #ifdef DEBUG_FLAG
        printf("ristretto255_decode: Bad encoding or neg bytes passed to the ristretto255_decode function! is_canonical=%d, is_negative=%d\n", is_canonical, is_negative);
    #endif
    return 1;
  }

  // Step 2 calc ristretto255/ge25519 point
  // a = ± 1
  #define _ss temp2
  #define u1 temp3
  #define u2 temp4
  

  pow2(_ss,_s);                           //s^2
  fsub(u1,F_ONE,_ss);                     // u1 = 1 + as^2
  fadd(u2,F_ONE,_ss);                     // u2 = 1 - as^2

  
  #define uu1 temp5
  pow2(uu1,u1);                           // u1^2
  
  // d == EDWARDS_D-> from ristretto darft
  #define duu1_positive temp6
  fmul(duu1_positive,EDWARDS_D,uu1);      // D*u1^2
  #define duu1 temp5
  fneg(duu1,duu1_positive);               // -(D * u1^2) 

  #define uu2 temp6
  pow2(uu2,u2);                           // u2^2
  #define _v temp2
  fsub(_v,duu1,uu2);                      // -(D * u1^2) - u2_sqr
  #define vuu2 temp5
  fmul(vuu2,_v,uu2);                      // v * u2_sqr

  #define _I temp6
  was_square = inv_sqrt(_I,F_ONE,vuu2);   // (was_square, invsqrt) = SQRT_RATIO_M1(1, v * u2_sqr)

  #define Dx temp5
  fmul(Dx,_I,u2);                         // den_x = invsqrt * u2
  #define Dxv temp4
  fmul(Dxv, Dx, _v);                      // den_x * v


  #define sDx temp2
  fmul(sDx,_s,Dx);                        // s*den_x
  fadd(ristretto_out->x,sDx,sDx);         // 2*s*den_x
  fabsolute(ristretto_out->x,ristretto_out->x); // x = CT_ABS(2 * s * den_x)

  #define Dy temp5
  fmul(Dy, _I, Dxv);                      // den_y = invsqrt * den_x * v

  fmul(ristretto_out->y,u1,Dy);           // y = u1 * den_y

  fmul(ristretto_out->t,ristretto_out->x,ristretto_out->y); // t = x * y

  fcopy(ristretto_out->z, F_ONE);         // z is set to 1

  WIPE_BUFFER(_s); WIPE_BUFFER(sDx); WIPE_BUFFER(u1);
  WIPE_BUFFER(Dxv); WIPE_BUFFER(Dy); WIPE_BUFFER(_I);

  if (was_square == 0){
    #ifdef DEBUG_FLAG
      printf("\n\n\n ristretto255_decode: Bad encoding! was_square=%d \n\n\n",was_square);
    #endif
    return 1;
  }
  if (is_neg(ristretto_out->t)){
    #ifdef DEBUG_FLAG
      printf("\n\n\n ristretto255_decode: Bad encoding! is_neg(t)=%d \n\n\n",is_neg(ristretto_out->t));
    #endif
    return 1;
  }
  if (feq(ristretto_out->y,F_ZERO)){
    #ifdef DEBUG_FLAG
      printf("\n\n\n ristretto255_decode: Bad encoding! feq(y,F_ZERO)=%d \n\n\n",feq(ristretto_out->y,F_ZERO));
    #endif
    return 1;
  }
  return 0;
}



/**
  * @brief Encode input ristretto255_point to output bytes u8[32]
  * @param[in]   -> ristretto_out ristretto255_point
  * @param[out]      -> bytes_out[32]
**/
// Inspired by ristretto draft
// encodes ristretto255 point to 32-word u8[32] element

// Note that we redefined temporary variables multiple times
// just to make code more readible. We also added comments
// at the end of the lines, so you will be able to compare
// every line with draft specification.
// DRAFT from 2023-09-18:
// https://datatracker.ietf.org/doc/draft-irtf-cfrg-ristretto255-decaf448/
// *** STACKSIZE: 420B + 5size_t ***
int ristretto255_encode(u8 bytes_out[BYTES_ELEM_SIZE], const ristretto255_point* ristretto_in){

  
  field_elem _temp1,_temp2,_temp3,_temp4,_temp5,_temp6,_temp7;


  #define temp_zy1 _temp1
  #define temp_zy2 _temp2
  #define u1_ _temp3
  fadd(temp_zy1,ristretto_in->z,ristretto_in->y);   // z0+y0
  fsub(temp_zy2,ristretto_in->z,ristretto_in->y);   // Z0-y0
  fmul(u1_,temp_zy1,temp_zy2);                      // u1=(z0+y0)(Z0-y0)

  #define u2_ _temp1
  fmul(u2_,ristretto_in->x,ristretto_in->y);        // u2=x0*y0

  #define uu2_ _temp2
  pow2(uu2_,u2_);                         //u2^2 
  #define u1uu2 _temp4
  fmul(u1uu2,u1_,uu2_);                   // u1 * u2^2
  #define I_ _temp2
  inv_sqrt(I_,F_ONE,u1uu2);               // (_, invsqrt) = SQRT_RATIO_M1(1, u1 * u2^2)

  #define D1_ _temp4
  fmul(D1_,u1_,I_);                       // den1 = invsqrt * u1
  #define D2_ _temp3
  fmul(D2_,u2_,I_);                       // den2 = invsqrt * u2

  #define D1D2 _temp1
  fmul(D1D2,D1_,D2_);                     // den1*den2
  #define Zinv _temp2
  fmul(Zinv,D1D2,ristretto_in->t);        // z_inv = den1 * den2 * t0
  

  #define enchanted_denominator _temp1
  fmul(enchanted_denominator,D1_,INVSQRT_A_MINUS_D); // enchanted_denominator = den1 * INVSQRT_A_MINUS_D
  #define tZinv _temp4
  fmul(tZinv,ristretto_in->t,Zinv);       // t0 * z_inv
  
  // note: we used swap25519 instead of fselect so our logic
  // is little bit different here
  int is_tZinv_neg = 1-is_neg(tZinv);     // IS_NEGATIVE(t0 * z_inv)
  #define _X _temp4
  #define _Y _temp5
  fcopy(_X,ristretto_in->x);
  fcopy(_Y,ristretto_in->y);

  #define iX _temp6
  #define iY _temp7
  fmul(iX, ristretto_in->x, SQRT_M1);     // ix0 = x0 * SQRT_M1
  fmul(iY, ristretto_in->y, SQRT_M1);     // iy0 = y0 * SQRT_M1
  swap25519(iY,_X,is_tZinv_neg);          // y = CT_SELECT(ix0 IF rotate ELSE y0)
  swap25519(iX,_Y,is_tZinv_neg);          // x = CT_SELECT(iy0 IF rotate ELSE x0)
  swap25519(enchanted_denominator,D2_,is_tZinv_neg); // den_inv = CT_SELECT(enchanted_denominator IF rotate ELSE den2)  

  #define XZ_inv _temp3
  fmul(XZ_inv,iY,Zinv);                   // x * z_inv
  #define n_Y _temp2
  fneg(n_Y,iX);                           // -(x * z_inv)
  fcopy(iX,iX); 
  swap25519(iX,n_Y,is_neg(XZ_inv));       // y = CT_SELECT(-y IF IS_NEGATIVE(x * z_inv) ELSE y)

  #define _Z _temp3
  fcopy(_Z,ristretto_in->z);

  #define Z_Y _temp2
  fsub(Z_Y,_Z,iX);                        // (z - y)

  #define temp_s _temp3
  fmul(temp_s,enchanted_denominator,Z_Y); // den_inv * (z - y)


  fabsolute(temp_s,temp_s);               // s = CT_ABS(den_inv * (z - y))
  
  pack25519(bytes_out,temp_s);

  WIPE_BUFFER(enchanted_denominator); WIPE_BUFFER(Z_Y); WIPE_BUFFER(temp_s);
  WIPE_BUFFER(_X); WIPE_BUFFER(_Y); WIPE_BUFFER(iX);
  WIPE_BUFFER(iY);
  return 0;
}



/**
  * @brief Turns hash bytes[32] into valid ristretto point in GF
  * @param[in]   -> bytes_in[32]
  * @param[out]  -> bytes_out[32]
**/

// Inspired by ristretto draft
// hash_to_group or element derivation function takes 
// hash input and turn it into valid ristretto point.
// In this implementation, input is hexa-string (see more below)
// hash_to_group function consists of 3 steps:
// 1) divide input into 2 halves and mask both hlaves
// 2) MAP both halves so out get 2 points represented 
// with X,Y,Z,T coords (Extended edward's coords)
//
// 3) perform addition of 2 edward's point, note that
// we need to add 2 edwards points so fe25519 arithmetics won't 
// fit there we need to use function that adds 2 edwards points
// *** STACKSIZE: 804B + 5size_t + 2x int***
int hash_to_group(u8 bytes_out[BYTES_ELEM_SIZE], const u8 bytes_in[HASH_BYTES_SIZE]){
  ristretto255_point a_point;
  ristretto255_point *a = &a_point;

  ristretto255_point b_point;
  ristretto255_point *b = &b_point;

  ristretto255_point r_point;
  ristretto255_point *r = &r_point;
  

  // make halves
  u8 t1[32], t2[32];
  b_copy((uint32_t *)t1,(uint32_t *)bytes_in);
  b_copy((uint32_t *)t2,(uint32_t *) (bytes_in+32));

  
  // MASK LSB for each half, this is equivalent to modulo 2**255
  // This step is very important, if skipped, hash_to_group 
  // returns invalid elements
  t1[31] &= 0x7F;
  t2[31] &= 0x7F;

  // encode t1,t2 to field_elem

  field_elem ft1,ft2;
  unpack25519(ft1,t1);
  unpack25519(ft2,t2);

  MAP(a,ft1); // map(ristretto_elligator) first half
  MAP(b,ft2); // map(ristretto_elligator) second hal

  ristretto255_point_addition(r,a,b); // addition of 2 Edward's point

  ristretto255_encode(bytes_out, r);

  WIPE_PT(&a_point); WIPE_PT(&b_point); WIPE_PT(&r_point);
  return 0;
}


/**
  * @brief Scalar multiplication of ristretto255_point
  * @param[in]   -> q ristretto255_point 
  * @param[in]   -> s ==> scalar 
  * @param[out]  -> p ristretto255_point
**/
// ristretto255_scalarmult() => scalar multiplication 
// ristretto_point q * scalar s
// Note that scalar "s" is represented as u8[32]
// Inspired by tweetNaCl: https://github.com/dominictarr/tweetnacl/blob/master/tweetnacl.c#L632
// *** STACKSIZE: 293B+ 4size_t +int***
void ristretto255_scalarmult(ristretto255_point* p, ristretto255_point* q,const u8 *s){
  fcopy(p->x,F_ZERO);
  fcopy(p->y,F_ONE);
  fcopy(p->z,F_ONE);
  fcopy(p->t,F_ZERO);
  for (int i = 255;i >= 0;--i) {
    u8 b = (s[i/8]>>(i&7))&1;
    cswap(p,q,b);
    ristretto255_point_addition(q,q,p);
    ristretto255_point_addition(p,p,p);
    cswap(p,q,b);
  }
}




































