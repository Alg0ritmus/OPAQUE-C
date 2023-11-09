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
  * This file includes 3 functions taken from crypto library 
  * MonoCypher. We extracted and  slightly edited functions
  * that perform modular inverse (arithmetic modulo L). 
  * These functions are suitable for creation of other protocols 
  * like OPAQUE etc. 
  *
  * Note that mod_l() are build on Barrett reduction which
  * is used later in inverse_mod_l(); which can be suboptimal,
  * even though we reuse temp. space on stack. More efficient way
  * (in some cases, see modl.h) is to use Montgomery reduction.
  * Due to efficieny we slightly edited crypto_x25519_inverse()
  * to perform Montgomery reduction. 
  * 
  * NOTE: Extracted and edited code is functional only on 
  * Litle Endian architecture (at least for now)!
**/

#include "modl.h" 

//////////////////
// MONOCYPHER - needed for efficient calculation of a mod L
/////////////////
/// Utilities ///
/////////////////
static void store32_le(u8 out[4], u32 in){
    out[0] =  in        & 0xff;
    out[1] = (in >>  8) & 0xff;
    out[2] = (in >> 16) & 0xff;
    out[3] = (in >> 24) & 0xff;
}

void store32_le_buf(u8 *dst, const u32 *src, size_t size) {
    size_t i;
    FOR(i, 0, size) { store32_le(dst + i*4, src[i]); }
}

// get bit from scalar at position i
static int scalar_bit(const u8 s[BYTES_ELEM_SIZE], int i){
    if (i < 0) { return 0; } // handle -1 for sliding windows
    return (s[i>>3] >> (i&7)) & 1;
}


///////////////////////////
/// Arithmetic modulo L ///
///////////////////////////

// Note that L = 2^252+27742317777372353535851937790883648493
// Which is goup order.
static const u32 L[8] = {
    0x5cf5d3ed, 0x5812631a, 0xa2f79cd6, 0x14def9de,
    0x00000000, 0x00000000, 0x00000000, 0x10000000,
};

//  p = a*b + p
static void multiply(u32 p[16], const u32 a[8], const u32 b[8]){
   size_t i, j;
    FOR (i, 0, 8) {
        u64 carry = 0;
        FOR (j, 0, 8) {
            carry  += p[i+j] + (u64)a[i] * b[j];
            p[i+j]  = (u32)carry;
            carry >>= 32;
        }
        p[i+8] = (u32)carry;
    }
}

static int is_above_l(const u32 x[8]){
   size_t i;
    // We work with L directly, in a 2's complement encoding
    // (-L == ~L + 1)
    u64 carry = 1;
    FOR (i, 0, 8) {
        carry  += (u64)x[i] + (~L[i] & 0xffffffff);
        carry >>= 32;
    }
    return (int)carry; // carry is either 0 or 1
}

// Final reduction modulo L, by conditionally removing L.
// if x < l     , then r = x
// if l <= x 2*l, then r = x-l
// otherwise the result will be wrong
static void remove_l(u32 r[8], const u32 x[8]){
   size_t i;
    u64 carry = (u64)is_above_l(x);
    u32 mask  = ~(u32)carry + 1; // carry == 0 or 1
    FOR (i, 0, 8) {
        carry += (u64)x[i] + (~L[i] & mask);
        r[i]   = (u32)carry;
        carry >>= 32;
    }
}

// Full reduction modulo L (Barrett reduction)
void mod_l(u8 reduced[32], const u32 x[16]){
   size_t i, j;
    // r[9] is precomputed value for internal purposes 
    // used during calculation in Barrett reduction algorithm.
    // r :=  b^(2k)/L, where:
    // b := 2^32,  number of combinations in a 1 word (u32 -> 32bits)
    // k := 8, number of words of modulus (u32 L[8])
    // formula := floor(b^2k/L)
    // floor(b^2k/L) = floor((2^32)^16/L) = floor(2^512/L)
    static const u32 r[9] = { 
        0x0a2c131b,0xed9ce5a3,0x086329a7,0x2106215d,
        0xffffffeb,0xffffffff,0xffffffff,0xffffffff,0xf,
    };
    // xr = x * r
    u32 xr[25] = {0};
    FOR (i, 0, 9) {
        u64 carry = 0;
        FOR (j, 0, 16) {
            carry  += xr[i+j] + (u64)r[i] * x[j];
            xr[i+j] = (u32)carry;
            carry >>= 32;
        }
        xr[i+16] = (u32)carry;
    }
    // xr = floor(xr / 2^512) * L
    // Since the result is guaranteed to be below 2*L,
    // it is enough to only compute the first 256 bits.
    // The division is performed by saying xr[i+16]. (16 * 32 = 512)
    ZERO(i, xr, 8);
    FOR (i, 0, 8) {
        u64 carry = 0;
        FOR (j, 0, 8-i) {
            carry   += xr[i+j] + (u64)xr[i+16] * L[j];
            xr[i+j] = (u32)carry;
            carry >>= 32;
        }
    }
    // xr = x - xr
    u64 carry = 1;
    FOR (i, 0, 8) {
        carry  += (u64)x[i] + (~xr[i] & 0xffffffff);
        xr[i]   = (u32)carry;
        carry >>= 32;
    }
    // Final reduction modulo L (conditional subtraction)
    remove_l(xr, xr);
    store32_le_buf(reduced, xr, 8);

    WIPE_BUFFER(xr);
}


/********************* WARNING ********************************/
// Functional only on CPU with Little Endian architecture!
// Feature for Big Endian architecture is not implemented (yet). 

// MONTGOMERY implementation of modular inverse (mod l).
// More efficient in some ways (). See modl.h
#ifdef MONTGOMERY_MODL_INVERSE_FLAG

static u32 load32_le(const u8 s[4])
{
    return
        ((u32)s[0] <<  0) |
        ((u32)s[1] <<  8) |
        ((u32)s[2] << 16) |
        ((u32)s[3] << 24);
}

static void load32_le_buf (u32 *dst, const u8 *src, size_t size) {
    size_t i;
    FOR(i, 0, size) { dst[i] = load32_le(src + i*4); }
}


///////////////////////
/// Scalar division ///
///////////////////////

// Montgomery reduction.
// Divides x by (2^256), and reduces the result modulo L
//
// Precondition:
//   x < L * 2^256
// Constants:
//   r = 2^256                 (makes division by r trivial)
//   k = (r * (1/r) - 1) // L  (1/r is computed modulo L, note that this is done by inverse modL)
// Algorithm:
//   s = (x * k) % r
//   t = x + s*L      (t is always a multiple of r)
//   u = (t/r) % L    (u is always below 2*L, conditional subtraction is enough)
static void redc(u32 u[8], u32 x[16])
{
    // k = (r * (1/r) - 1) // L  (1/r is computed modulo L, note that this is done by inverse modL)
    // Note that pseudo code would look like this: (r * inv_mod_l(1,r) - 1) // L
    // where '//' denotes  floor division e.g. 4//3 = 1 
    static const u32 k[8] = {
        0x12547e1b, 0xd2b51da3, 0xfdba84ff, 0xb1a206f2,
        0xffa36bea, 0x14e75438, 0x6fe91836, 0x9db6c6f2,
    };

    // s = x * k (modulo 2^256)
    // This is cheaper than the full multiplication.
    u32 s[8] = {0};
    size_t idx;
    
    FOR (idx, 0, 8) {
        u64 carry = 0;
        size_t jdx;
        FOR (jdx, 0, 8-idx) {
            carry  += s[idx+jdx] + (u64)x[idx] * k[jdx];
            s[idx+jdx]  = (u32)carry;
            carry >>= 32;
        }
    }
    u32 t[16] = {0};
    multiply(t, s, L);

    // t = t + x
    size_t index;
    u64 carry = 0;
    FOR (index, 0, 16) {
        carry  += (u64)t[index] + x[index];
        t[index]    = (u32)carry;
        carry >>= 32;
    }

    // u = (t / 2^256) % L
    // Note that t / 2^256 is always below 2*L,
    // So a constant time conditional subtraction is enough
    remove_l(u, t+8);

    WIPE_BUFFER(s);
    WIPE_BUFFER(t);
}


void crypto_x25519_inverse(u8 out[BYTES_ELEM_SIZE], const u8 in[BYTES_ELEM_SIZE])
{
    static const  u8 Lm2[32] = { // L - 2, where L = 2**252+27742317777372353535851937790883648493
        0xeb, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    };
    // 1 in Montgomery form
    u32 m_inv [8] = {
        0x8d98951d, 0xd6ec3174, 0x737dcf70, 0xc6ef5bf4,
        0xfffffffe, 0xffffffff, 0xffffffff, 0x0fffffff,
    };

    // Convert the scalar in Montgomery form
    // m_scl = scalar * 2^256 (modulo L)
    u32 m_scl[8];
    {
        size_t i;
        u32 tmp[16];
        ZERO(i, tmp, 8);
        load32_le_buf(tmp+8, in, 8);
        mod_l(out, tmp);
        load32_le_buf(m_scl, out, 8);
        WIPE_BUFFER(tmp); // Wipe ASAP to save stack space
    }

    // Compute the inverse
    u32 product[16];
    

    for (int i = 252; i >= 0; i--) {
        size_t jdx;
        ZERO(jdx, product, 16);
        multiply(product, m_inv, m_inv);
        redc(m_inv, product);
        if (scalar_bit(Lm2, i)) {
            size_t jdnx; 
            ZERO(jdnx, product, 16);
            multiply(product, m_inv, m_scl);
            redc(m_inv, product);
        }
    }
    // Convert the inverse *out* of Montgomery form
    // scalar = m_inv / 2^256 (modulo L)
    size_t jdx1;
    size_t jdx2;
    COPY(jdx1, product, m_inv, 8);
    ZERO(jdx2, product + 8, 8);
    redc(m_inv, product);
    store32_le_buf(out, m_inv, 8); // the *inverse* of the scalar

    WIPE_BUFFER(m_scl);
    WIPE_BUFFER(product);  WIPE_BUFFER(m_inv);
}
#else //Barrett reduction
/********************* WARNING ********************************/
// Functional only on CPU with Little Endian architecture!
// Feature for Big Endian architecture is not implemented (yet). 
static void multiply_mod_l(u32 r[8], const u32 a[8], const u32 b[8]){
    u32 c[16] = {0};
    multiply(c, a, b);
    mod_l((u8*) r, c);
    WIPE_BUFFER(c);
}


// code that uses temporary memory-space on stack
void inverse_mod_l(u8 out[BYTES_ELEM_SIZE], const u8 in[BYTES_ELEM_SIZE]){
    static u8 Lm2[BYTES_ELEM_SIZE] = { // L - 2
        0xeb, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    };
    u32 m_inv [8] = {1};
    // Compute the inverse
    for (int i = 252; i >= 0; i--) {
        multiply_mod_l(m_inv, m_inv, m_inv);
        if (scalar_bit(Lm2, i)) {

            multiply_mod_l(m_inv, m_inv, (u32*) in);

        }
    }
    int i;
    COPY(i ,out, (u8*) m_inv, BYTES_ELEM_SIZE);
    WIPE_BUFFER(m_inv);
}
#endif