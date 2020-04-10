#import <React/RCTBridgeModule.h>

@interface BlueCrypto : NSObject <RCTBridgeModule>

@end






















#ifndef SIZE_MAX
#    if defined(__LP64__)
#        define SIZE_MAX       UINT64_MAX
#    else
#        define SIZE_MAX       UINT32_MAX
#    endif
#endif



/* BASE64 libraries used internally - should not need to be packaged */

#define b64_encode_len(A) ((A+2)/3 * 4 + 1)
#define b64_decode_len(A) (A / 4 * 3 + 2)

int    libscrypt_b64_encode(unsigned char const *src, size_t srclength,
        /*@out@*/ char *target, size_t targetsize);
int    libscrypt_b64_decode(char const *src, /*@out@*/ unsigned char *target,
        size_t targetsize);




#include <stdint.h>

/**
 * Converts a binary string to a hex representation of that string
 * outbuf must have size of at least buf * 2 + 1.
 */
/*int libscrypt_hexconvert(const uint8_t *buf, size_t s, char *outbuf,
    size_t obs);
*/

/*-
 */
#ifndef _CRYPTO_SCRYPT_H_
#define _CRYPTO_SCRYPT_H_



#ifdef __cplusplus
extern "C"{
#endif

/**
 * crypto_scrypt(passwd, passwdlen, salt, saltlen, N, r, p, buf, buflen):
 * Compute scrypt(passwd[0 .. passwdlen - 1], salt[0 .. saltlen - 1], N, r,
 * p, buflen) and write the result into buf.  The parameters r, p, and buflen
 * must satisfy r * p < 2^30 and buflen <= (2^32 - 1) * 32.  The parameter N
 * must be a power of 2 greater than 1.
 *
 * libscrypt_scrypt(passwd, passwdlen, salt, saltlen, N, r, p, buf, buflen):
 * password; duh
 * N: CPU AND RAM cost (first modifier)
 * r: RAM Cost
 * p: CPU cost (parallelisation)
 * In short, N is your main performance modifier. Values of r = 8, p = 1 are
 * standard unless you want to modify the CPU/RAM ratio.
 * Return 0 on success; or -1 on error.
 */
int libscrypt_scrypt(const uint8_t *, size_t, const uint8_t *, size_t, uint64_t,
    uint32_t, uint32_t, /*@out@*/ uint8_t *, size_t);

/* Converts a series of input parameters to a MCF form for storage */
int libscrypt_mcf(uint32_t N, uint32_t r, uint32_t p, const char *salt,
    const char *hash, char *mcf);

#ifndef _MSC_VER
/* Generates a salt. Uses /dev/urandom/
 */
int libscrypt_salt_gen(/*@out@*/ uint8_t *rand, size_t len);

/* Creates a hash of a passphrase using a randomly generated salt */
/* Returns >0 on success, or 0 for fail */
int libscrypt_hash(char *dst, const char* passphrase, uint32_t N, uint8_t r,
  uint8_t p);
#endif

/* Checks a given MCF against a password */
int libscrypt_check(char *mcf, const char *password);

#ifdef __cplusplus
}
#endif

/* Sane default values */
#define SCRYPT_HASH_LEN 64 /* This can be user defined -
 *but 64 is the reference size
 */
#define SCRYPT_SAFE_N 30 /* This is much higher than you want. It's just
              * a blocker for insane defines
              */
#define SCRYPT_SALT_LEN 16 /* This is just a recommended size */
#define SCRYPT_MCF_LEN 125 /* mcf is 120 byte + nul */
#define SCRYPT_MCF_ID "$s1"
#define SCRYPT_N 16384
#define SCRYPT_r 8
#define SCRYPT_p 16
#endif /* !_CRYPTO_SCRYPT_H_ */




/*-
 * Copyright 2005,2007,2009 Colin Percival
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: src/lib/libmd/sha256.h,v 1.2 2006/01/17 15:35:56 phk Exp $
 */

#ifndef _SHA256_H_
#define _SHA256_H_

#include <sys/types.h>


typedef struct libscrypt_SHA256Context {
    uint32_t state[8];
    uint32_t count[2];
    unsigned char buf[64];
} SHA256_CTX;

typedef struct libscrypt_HMAC_SHA256Context {
    SHA256_CTX ictx;
    SHA256_CTX octx;
} HMAC_SHA256_CTX;

void    libscrypt_SHA256_Init(/*@out@*/ SHA256_CTX *);
void    libscrypt_SHA256_Update(SHA256_CTX *, const void *, size_t);

/* Original declaration:
 *    void    SHA256_Final(unsigned char [32], SHA256_CTX *);
*/
void    libscrypt_SHA256_Final(/*@out@*/ unsigned char [], SHA256_CTX *);
void    libscrypt_HMAC_SHA256_Init(HMAC_SHA256_CTX *, const void *, size_t);
void    libscrypt_HMAC_SHA256_Update(HMAC_SHA256_CTX *, const void *, size_t);

/* Original declaration:
 *    void    HMAC_SHA256_Final(unsigned char [32], HMAC_SHA256_CTX *);
*/
void    libscrypt_HMAC_SHA256_Final(unsigned char [], HMAC_SHA256_CTX *);

/**
 * PBKDF2_SHA256(passwd, passwdlen, salt, saltlen, c, buf, dkLen):
 * Compute PBKDF2(passwd, salt, c, dkLen) using HMAC-SHA256 as the PRF, and
 * write the output to buf.  The value dkLen must be at most 32 * (2^32 - 1).
 */
void    libscrypt_PBKDF2_SHA256(const uint8_t *, size_t, const uint8_t *, size_t,
    uint64_t, uint8_t *, size_t);

#endif /* !_SHA256_H_ */



/* Implements a constant time version of strcmp()
 * Will return 1 if a and b are equal, 0 if they are not */
int slow_equals(const char* a, const char* b);




/*-
 * Copyright 2007-2009 Colin Percival
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file was originally written by Colin Percival as part of the Tarsnap
 * online backup system.
 */
#ifndef _SYSENDIAN_H_
#define _SYSENDIAN_H_


/* If we don't have be64enc, the <sys/endian.h> we have isn't usable. */
#if !HAVE_DECL_BE64ENC
#undef HAVE_SYS_ENDIAN_H
#endif

#ifdef HAVE_SYS_ENDIAN_H

#include <sys/endian.h>

#else

#ifdef _MSC_VER
  #define INLINE __inline
#else
  #define INLINE inline
#endif

static INLINE uint32_t
be32dec(const void *pp)
{
    const uint8_t *p = (uint8_t const *)pp;

    return ((uint32_t)(p[3]) + ((uint32_t)(p[2]) << 8) +
        ((uint32_t)(p[1]) << 16) + ((uint32_t)(p[0]) << 24));
}

static INLINE void
be32enc(void *pp, uint32_t x)
{
    uint8_t * p = (uint8_t *)pp;

    p[3] = x & 0xff;
    p[2] = (x >> 8) & 0xff;
    p[1] = (x >> 16) & 0xff;
    p[0] = (x >> 24) & 0xff;
}

static INLINE uint64_t
be64dec(const void *pp)
{
    const uint8_t *p = (uint8_t const *)pp;

    return ((uint64_t)(p[7]) + ((uint64_t)(p[6]) << 8) +
        ((uint64_t)(p[5]) << 16) + ((uint64_t)(p[4]) << 24) +
        ((uint64_t)(p[3]) << 32) + ((uint64_t)(p[2]) << 40) +
        ((uint64_t)(p[1]) << 48) + ((uint64_t)(p[0]) << 56));
}

static INLINE void
be64enc(void *pp, uint64_t x)
{
    uint8_t * p = (uint8_t *)pp;

    p[7] = x & 0xff;
    p[6] = (x >> 8) & 0xff;
    p[5] = (x >> 16) & 0xff;
    p[4] = (x >> 24) & 0xff;
    p[3] = (x >> 32) & 0xff;
    p[2] = (x >> 40) & 0xff;
    p[1] = (x >> 48) & 0xff;
    p[0] = (x >> 56) & 0xff;
}

static INLINE uint32_t
le32dec(const void *pp)
{
    const uint8_t *p = (uint8_t const *)pp;

    return ((uint32_t)(p[0]) + ((uint32_t)(p[1]) << 8) +
        ((uint32_t)(p[2]) << 16) + ((uint32_t)(p[3]) << 24));
}

static INLINE void
le32enc(void *pp, uint32_t x)
{
    uint8_t * p = (uint8_t *)pp;

    p[0] = x & 0xff;
    p[1] = (x >> 8) & 0xff;
    p[2] = (x >> 16) & 0xff;
    p[3] = (x >> 24) & 0xff;
}

static INLINE uint64_t
le64dec(const void *pp)
{
    const uint8_t *p = (uint8_t const *)pp;

    return ((uint64_t)(p[0]) + ((uint64_t)(p[1]) << 8) +
        ((uint64_t)(p[2]) << 16) + ((uint64_t)(p[3]) << 24) +
        ((uint64_t)(p[4]) << 32) + ((uint64_t)(p[5]) << 40) +
        ((uint64_t)(p[6]) << 48) + ((uint64_t)(p[7]) << 56));
}

static INLINE void
le64enc(void *pp, uint64_t x)
{
    uint8_t * p = (uint8_t *)pp;

    p[0] = x & 0xff;
    p[1] = (x >> 8) & 0xff;
    p[2] = (x >> 16) & 0xff;
    p[3] = (x >> 24) & 0xff;
    p[4] = (x >> 32) & 0xff;
    p[5] = (x >> 40) & 0xff;
    p[6] = (x >> 48) & 0xff;
    p[7] = (x >> 56) & 0xff;
}
#endif /* !HAVE_SYS_ENDIAN_H */

#endif /* !_SYSENDIAN_H_ */



