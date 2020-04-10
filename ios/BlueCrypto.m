#import "BlueCrypto.h"


@implementation BlueCrypto

RCT_EXPORT_MODULE()



RCT_REMAP_METHOD(scrypt, scrypt:(NSString *)passwd
                 salt:(NSArray *)salt
                 N:(NSUInteger)N
                 r:(NSUInteger)r
                 p:(NSUInteger)p
                 dkLen:(NSUInteger)dkLen
                 resolver:(RCTPromiseResolveBlock)resolve
                 rejecter:(RCTPromiseRejectBlock)reject)
{
    int i, success;
    size_t saltLength;
    uint8_t hashbuf[dkLen];
    const uint8_t *parsedSalt;
    uint8_t *buffer = NULL;
    const char* passphrase = [passwd UTF8String];

    saltLength = (int) [salt count];
    buffer = malloc(sizeof(uint8_t) * saltLength);
    for (i = 0; i < saltLength; ++i) {
        buffer[i] = (uint8_t)[[salt objectAtIndex:i] integerValue];
    }
    parsedSalt = buffer;



    @try {
        success = libscrypt_scrypt((uint8_t *)passphrase, strlen(passphrase), parsedSalt, saltLength, N, r, p, hashbuf, dkLen);
    }
    @catch (NSException * e) {
        NSError *error = [NSError errorWithDomain:@"com.crypho.scrypt" code:200 userInfo:@{@"Error reason": @"Error in scrypt"}];
        reject(@"Failure in scrypt", @"Error", error);
    }

    NSMutableString *hexResult = [NSMutableString stringWithCapacity:dkLen * 2];
    for(i = 0;i < dkLen; i++ )
    {
        [hexResult appendFormat:@"%02x", hashbuf[i]];
    }
    NSString *result = [NSString stringWithString: hexResult];
    resolve(result);
    free(buffer);
}

@end








































































/*
 * Copyright (c) 1996 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

/*
 * Portions Copyright (c) 1995 by International Business Machines, Inc.
 *
 * International Business Machines, Inc. (hereinafter called IBM) grants
 * permission under its copyrights to use, copy, modify, and distribute this
 * Software with or without fee, provided that the above copyright notice and
 * all paragraphs of this notice appear in all copies, and that the name of IBM
 * not be used in connection with the marketing of any product incorporating
 * the Software or modifications thereof, without specific, written prior
 * permission.
 *
 * To the extent it has a right to do so, IBM grants an immunity from suit
 * under its patents, if any, for the use, sale or manufacture of products to
 * the extent that such products are used for performing Domain Name System
 * dynamic updates in TCP/IP networks by means of the Software.  No immunity is
 * granted for any product per se or for any other function of any product.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", AND IBM DISCLAIMS ALL WARRANTIES,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE.  IN NO EVENT SHALL IBM BE LIABLE FOR ANY SPECIAL,
 * DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE, EVEN
 * IF IBM IS APPRISED OF THE POSSIBILITY OF SUCH DAMAGES.
 */

/*
 * Base64 encode/decode functions from OpenBSD (src/lib/libc/net/base64.c).
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>


static const char Base64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char Pad64 = '=';

/* (From RFC1521 and draft-ietf-dnssec-secext-03.txt)
   The following encoding technique is taken from RFC 1521 by Borenstein
   and Freed.  It is reproduced here in a slightly edited form for
   convenience.

   A 65-character subset of US-ASCII is used, enabling 6 bits to be
   represented per printable character. (The extra 65th character, "=",
   is used to signify a special processing function.)

   The encoding process represents 24-bit groups of input bits as output
   strings of 4 encoded characters. Proceeding from left to right, a
   24-bit input group is formed by concatenating 3 8-bit input groups.
   These 24 bits are then treated as 4 concatenated 6-bit groups, each
   of which is translated into a single digit in the base64 alphabet.

   Each 6-bit group is used as an index into an array of 64 printable
   characters. The character referenced by the index is placed in the
   output string.

                         Table 1: The Base64 Alphabet

      Value Encoding  Value Encoding  Value Encoding  Value Encoding
          0 A            17 R            34 i            51 z
          1 B            18 S            35 j            52 0
          2 C            19 T            36 k            53 1
          3 D            20 U            37 l            54 2
          4 E            21 V            38 m            55 3
          5 F            22 W            39 n            56 4
          6 G            23 X            40 o            57 5
          7 H            24 Y            41 p            58 6
          8 I            25 Z            42 q            59 7
          9 J            26 a            43 r            60 8
         10 K            27 b            44 s            61 9
         11 L            28 c            45 t            62 +
         12 M            29 d            46 u            63 /
         13 N            30 e            47 v
         14 O            31 f            48 w         (pad) =
         15 P            32 g            49 x
         16 Q            33 h            50 y

   Special processing is performed if fewer than 24 bits are available
   at the end of the data being encoded.  A full encoding quantum is
   always completed at the end of a quantity.  When fewer than 24 input
   bits are available in an input group, zero bits are added (on the
   right) to form an integral number of 6-bit groups.  Padding at the
   end of the data is performed using the '=' character.

   Since all base64 input is an integral number of octets, only the
         -------------------------------------------------
   following cases can arise:

       (1) the final quantum of encoding input is an integral
           multiple of 24 bits; here, the final unit of encoded
       output will be an integral multiple of 4 characters
       with no "=" padding,
       (2) the final quantum of encoding input is exactly 8 bits;
           here, the final unit of encoded output will be two
       characters followed by two "=" padding characters, or
       (3) the final quantum of encoding input is exactly 16 bits;
           here, the final unit of encoded output will be three
       characters followed by one "=" padding character.
*/

int
libscrypt_b64_encode(src, srclength, target, targsize)
    unsigned char const *src;
    size_t srclength;
    char *target;
    size_t targsize;
{
    size_t datalength = 0;
    unsigned char input[3];
    unsigned char output[4];
    unsigned int i;

    while (2 < srclength) {
        input[0] = *src++;
        input[1] = *src++;
        input[2] = *src++;
        srclength -= 3;

        output[0] = input[0] >> 2;
        output[1] = ((input[0] & 0x03) << 4) + (input[1] >> 4);
        output[2] = ((input[1] & 0x0f) << 2) + (input[2] >> 6);
        output[3] = input[2] & 0x3f;

        if (datalength + 4 > targsize)
            return (-1);
        target[datalength++] = Base64[output[0]];
        target[datalength++] = Base64[output[1]];
        target[datalength++] = Base64[output[2]];
        target[datalength++] = Base64[output[3]];
    }

    /* Now we worry about padding. */
    if (0 != srclength) {
        /* Get what's left. */
        input[0] = input[1] = input[2] = '\0';
        for (i = 0; i < srclength; i++)
            input[i] = *src++;

        output[0] = input[0] >> 2;
        output[1] = ((input[0] & 0x03) << 4) + (input[1] >> 4);
        output[2] = ((input[1] & 0x0f) << 2) + (input[2] >> 6);

        if (datalength + 4 > targsize)
            return (-1);
        target[datalength++] = Base64[output[0]];
        target[datalength++] = Base64[output[1]];
        if (srclength == 1)
            target[datalength++] = Pad64;
        else
            target[datalength++] = Base64[output[2]];
        target[datalength++] = Pad64;
    }
    if (datalength >= targsize)
        return (-1);
    target[datalength] = '\0';    /* Returned value doesn't count \0. */
    return (int)(datalength);
}

/* skips all whitespace anywhere.
   converts characters, four at a time, starting at (or after)
   src from base - 64 numbers into three 8 bit bytes in the target area.
   it returns the number of data bytes stored at the target, or -1 on error.
 */

int
libscrypt_b64_decode(src, target, targsize)
    char const *src;
    unsigned char *target;
    size_t targsize;
{
    int state, ch;
    unsigned int tarindex;
    unsigned char nextbyte;
    char *pos;

    state = 0;
    tarindex = 0;

    while ((ch = (unsigned char)*src++) != '\0') {
        if (isspace(ch))    /* Skip whitespace anywhere. */
            continue;

        if (ch == Pad64)
            break;

        pos = strchr(Base64, ch);
        if (pos == 0)         /* A non-base64 character. */
            return (-1);

        switch (state) {
        case 0:
            if (target) {
                if (tarindex >= targsize)
                    return (-1);
                target[tarindex] = (pos - Base64) << 2;
            }
            state = 1;
            break;
        case 1:
            if (target) {
                if (tarindex >= targsize)
                    return (-1);
                target[tarindex]   |=  (pos - Base64) >> 4;
                nextbyte = ((pos - Base64) & 0x0f) << 4;
                if (tarindex + 1 < targsize)
                    target[tarindex+1] = nextbyte;
                else if (nextbyte)
                    return (-1);
            }
            tarindex++;
            state = 2;
            break;
        case 2:
            if (target) {
                if (tarindex >= targsize)
                    return (-1);
                target[tarindex]   |=  (pos - Base64) >> 2;
                nextbyte = ((pos - Base64) & 0x03) << 6;
                if (tarindex + 1 < targsize)
                    target[tarindex+1] = nextbyte;
                else if (nextbyte)
                    return (-1);
            }
            tarindex++;
            state = 3;
            break;
        case 3:
            if (target) {
                if (tarindex >= targsize)
                    return (-1);
                target[tarindex] |= (pos - Base64);
            }
            tarindex++;
            state = 0;
            break;
        }
    }

    /*
     * We are done decoding Base-64 chars.  Let's see if we ended
     * on a byte boundary, and/or with erroneous trailing characters.
     */

    if (ch == Pad64) {            /* We got a pad char. */
        ch = (unsigned char)*src++;    /* Skip it, get next. */
        switch (state) {
        case 0:        /* Invalid = in first position */
        case 1:        /* Invalid = in second position */
            return (-1);

        case 2:        /* Valid, means one byte of info */
            /* Skip any number of spaces. */
            for (; ch != '\0'; ch = (unsigned char)*src++)
                if (!isspace(ch))
                    break;
            /* Make sure there is another trailing = sign. */
            if (ch != Pad64)
                return (-1);
            ch = (unsigned char)*src++;        /* Skip the = */
            /* Fall through to "single trailing =" case. */
            /* FALLTHROUGH */

        case 3:        /* Valid, means two bytes of info */
            /*
             * We know this char is an =.  Is there anything but
             * whitespace after it?
             */
            for (; ch != '\0'; ch = (unsigned char)*src++)
                if (!isspace(ch))
                    return (-1);

            /*
             * Now make sure for cases 2 and 3 that the "extra"
             * bits that slopped past the last full byte were
             * zeros.  If we don't check them, they become a
             * subliminal channel.
             */
            if (target && tarindex < targsize &&
                target[tarindex] != 0)
                return (-1);
        }
    } else {
        /*
         * We ended by seeing the end of the string.  Make sure we
         * have no partial bytes lying around.
         */
        if (state != 0)
            return (-1);
    }

    return (tarindex);
}




#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <float.h>
#include <stdint.h>
#include <math.h>

#ifndef S_SPLINT_S /* Including this here triggers a known bug in splint */
#include <unistd.h>
#endif


/* ilog2 for powers of two */
static uint32_t scrypt_ilog2(uint32_t n)
{
#ifndef S_SPLINT_S

    /* Check for a valid power of two */
    if (n < 2 || (n & (n - 1)))
        return -1;
#endif
    uint32_t t = 1;
    while (((uint32_t)1 << t) < n)
    {
        if(t > SCRYPT_SAFE_N)
            return (uint32_t) -1; /* Check for insanity */
        t++;
    }

    return t;
}

#ifdef _MSC_VER
  #define SNPRINTF _snprintf
#else
  #define SNPRINTF snprintf
#endif

int libscrypt_mcf(uint32_t N, uint32_t r, uint32_t p, const char *salt,
        const char *hash, char *mcf)
{

    uint32_t t, params;
    int s;

    if(!mcf || !hash)
        return 0;
    /* Although larger values of r, p are valid in scrypt, this mcf format
    * limits to 8 bits. If your number is larger, current computers will
    * struggle
    */
    if(r > (uint8_t)(-1) || p > (uint8_t)(-1))
        return 0;

    t = scrypt_ilog2(N);
    if (t < 1)
        return 0;
        
    params = (r << 8) + p;
    params += (uint32_t)t << 16;
    
    /* Using snprintf - not checking for overflows. We've already
    * determined that mcf should be defined as at least SCRYPT_MCF_LEN
    * in length
    */
    s = SNPRINTF(mcf, SCRYPT_MCF_LEN,  SCRYPT_MCF_ID "$%06x$%s$%s", (unsigned int)params, salt, hash);
    if (s > SCRYPT_MCF_LEN)
        return 0;

    return 1;
}





#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>

#ifndef S_SPLINT_S /* Including this here triggers a known bug in splint */
#include <unistd.h>
#endif

#define RNGDEV "/dev/urandom"

int libscrypt_salt_gen(uint8_t *salt, size_t len)
{
    unsigned char buf[len];
    size_t data_read = 0;
    int urandom = open(RNGDEV, O_RDONLY);

    if (urandom < 0)
    {
        return -1;
    }

    while (data_read < len) {
        ssize_t result = read(urandom, buf + data_read, len - data_read);

        if (result < 0)
        {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }

            else {
                (void)close(urandom);
                return -1;
            }
        }

        data_read += result;
    }

    /* Failures on close() shouldn't occur with O_RDONLY */
    (void)close(urandom);

    memcpy(salt, buf, len);

    return 0;
}





#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>


#ifdef _WIN32
/* On windows, strtok uses a thread-local static variable in strtok to
 * make strtok thread-safe.  It also neglects to provide a strtok_r. */
#define strtok_r(str, val, saveptr) strtok((str), (val))
#endif

int libscrypt_check(char *mcf, const char *password)
{
    /* Return values:
    * <0 error
    * == 0 password incorrect
    * >0 correct password
    */

#ifndef _WIN32
    char *saveptr = NULL;
#endif
    uint32_t params;
    uint64_t N;
    uint8_t r, p;
    int retval;
    uint8_t hashbuf[64];
    char outbuf[128];
    uint8_t salt[32];
    char *tok;

    if(memcmp(mcf, SCRYPT_MCF_ID, 3) != 0)
    {
        /* Only version 0 supported */
        return -1;
    }

    tok = strtok_r(mcf, "$", &saveptr);
    if ( !tok )
        return -1;

    tok = strtok_r(NULL, "$", &saveptr);

    if ( !tok )
        return -1;

    params = (uint32_t)strtoul(tok, NULL, 16);
    if ( params == 0 )
        return -1;

    tok = strtok_r(NULL, "$", &saveptr);

    if ( !tok )
        return -1;

    p = params & 0xff;
    r = (params >> 8) & 0xff;
    N = params >> 16;

    if (N > SCRYPT_SAFE_N)
        return -1;

    N = (uint64_t)1 << N;

    /* Useful debugging:
    printf("We've obtained salt 'N' r p of '%s' %d %d %d\n", tok, N,r,p);
    */

    memset(salt, 0, sizeof(salt)); /* Keeps splint happy */
    retval = libscrypt_b64_decode(tok, (unsigned char*)salt, sizeof(salt));
    if (retval < 1)
        return -1;

    retval = libscrypt_scrypt((uint8_t*)password, strlen(password), salt,
            (uint32_t)retval, N, r, p, hashbuf, sizeof(hashbuf));

    if (retval != 0)
        return -1;

    retval = libscrypt_b64_encode((unsigned char*)hashbuf, sizeof(hashbuf),
            outbuf, sizeof(outbuf));

    if (retval == 0)
        return -1;

    tok = strtok_r(NULL, "$", &saveptr);

    if ( !tok )
        return -1;

    if(slow_equals(tok, outbuf) == 0)
    {
        return 0;
    }

    return 1; /* This is the "else" condition */
}





#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>


int libscrypt_hash(char *dst, const char *passphrase, uint32_t N, uint8_t r,
        uint8_t p)
{

    int retval;
    uint8_t salt[SCRYPT_SALT_LEN];
    uint8_t    hashbuf[SCRYPT_HASH_LEN];
    char outbuf[256];
    char saltbuf[256];

    if(libscrypt_salt_gen(salt, SCRYPT_SALT_LEN) == -1)
    {
        return 0;
    }

    retval = libscrypt_scrypt((const uint8_t*)passphrase, strlen(passphrase),
            (uint8_t*)salt, SCRYPT_SALT_LEN, N, r, p, hashbuf, sizeof(hashbuf));
    if(retval == -1)
        return 0;

    retval = libscrypt_b64_encode((unsigned char*)hashbuf, sizeof(hashbuf),
            outbuf, sizeof(outbuf));
    if(retval == -1)
        return 0;
    
    retval = libscrypt_b64_encode((unsigned char *)salt, sizeof(salt),
            saltbuf, sizeof(saltbuf));
    if(retval == -1)
        return 0;

    retval = libscrypt_mcf(N, r, p, saltbuf, outbuf, dst);
    if(retval != 1)
        return 0;

    return 1;
}





#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

/* The hexconvert function is only used to test reference vectors against
 * known answers. The contents of this file are therefore a component
 * to assist with test harnesses only
 */

int libscrypt_hexconvert(uint8_t *buf, size_t s, char *outbuf, size_t obs)
{

        size_t i;
    int len = 0;

        if (!buf || s < 1 || obs < (s * 2 + 1))
                return 0;

        memset(outbuf, 0, obs);
    

        for(i=0; i<=(s-1); i++)
        {
        /* snprintf(outbuf, s,"%s...", outbuf....) has undefined results
        * and can't be used. Using offests like this makes snprintf
        * nontrivial. we therefore have use inescure sprintf() and
        * lengths checked elsewhere (start of function) */
        /*@ -bufferoverflowhigh @*/
                len += sprintf(outbuf+len, "%02x", (unsigned int) buf[i]);
        }

    return 1;
}







/*
 * Copyright 2009 Colin Percival
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

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>



static void blkcpy(uint8_t *, uint8_t *, size_t);
static void blkxor(uint8_t *, uint8_t *, size_t);
static void salsa20_8(uint8_t[64]);
static void blockmix_salsa8(uint8_t *, uint8_t *, size_t);
static uint64_t integerify(uint8_t *, size_t);
static void smix(uint8_t *, size_t, uint64_t, uint8_t *, uint8_t *);

static void
blkcpy(uint8_t * dest, uint8_t * src, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++)
        dest[i] = src[i];
}

static void
blkxor(uint8_t * dest, uint8_t * src, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++)
        dest[i] ^= src[i];
}

/**
 * salsa20_8(B):
 * Apply the salsa20/8 core to the provided block.
 */
static void
salsa20_8(uint8_t B[64])
{
    uint32_t B32[16];
    uint32_t x[16];
    size_t i;

    /* Convert little-endian values in. */
    for (i = 0; i < 16; i++)
        B32[i] = le32dec(&B[i * 4]);

    /* Compute x = doubleround^4(B32). */
    for (i = 0; i < 16; i++)
        x[i] = B32[i];
    for (i = 0; i < 8; i += 2) {
#define R(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
        /* Operate on columns. */
        x[ 4] ^= R(x[ 0]+x[12], 7);  x[ 8] ^= R(x[ 4]+x[ 0], 9);
        x[12] ^= R(x[ 8]+x[ 4],13);  x[ 0] ^= R(x[12]+x[ 8],18);

        x[ 9] ^= R(x[ 5]+x[ 1], 7);  x[13] ^= R(x[ 9]+x[ 5], 9);
        x[ 1] ^= R(x[13]+x[ 9],13);  x[ 5] ^= R(x[ 1]+x[13],18);

        x[14] ^= R(x[10]+x[ 6], 7);  x[ 2] ^= R(x[14]+x[10], 9);
        x[ 6] ^= R(x[ 2]+x[14],13);  x[10] ^= R(x[ 6]+x[ 2],18);

        x[ 3] ^= R(x[15]+x[11], 7);  x[ 7] ^= R(x[ 3]+x[15], 9);
        x[11] ^= R(x[ 7]+x[ 3],13);  x[15] ^= R(x[11]+x[ 7],18);

        /* Operate on rows. */
        x[ 1] ^= R(x[ 0]+x[ 3], 7);  x[ 2] ^= R(x[ 1]+x[ 0], 9);
        x[ 3] ^= R(x[ 2]+x[ 1],13);  x[ 0] ^= R(x[ 3]+x[ 2],18);

        x[ 6] ^= R(x[ 5]+x[ 4], 7);  x[ 7] ^= R(x[ 6]+x[ 5], 9);
        x[ 4] ^= R(x[ 7]+x[ 6],13);  x[ 5] ^= R(x[ 4]+x[ 7],18);

        x[11] ^= R(x[10]+x[ 9], 7);  x[ 8] ^= R(x[11]+x[10], 9);
        x[ 9] ^= R(x[ 8]+x[11],13);  x[10] ^= R(x[ 9]+x[ 8],18);

        x[12] ^= R(x[15]+x[14], 7);  x[13] ^= R(x[12]+x[15], 9);
        x[14] ^= R(x[13]+x[12],13);  x[15] ^= R(x[14]+x[13],18);
#undef R
    }

    /* Compute B32 = B32 + x. */
    for (i = 0; i < 16; i++)
        B32[i] += x[i];

    /* Convert little-endian values out. */
    for (i = 0; i < 16; i++)
        le32enc(&B[4 * i], B32[i]);
}

/**
 * blockmix_salsa8(B, Y, r):
 * Compute B = BlockMix_{salsa20/8, r}(B).  The input B must be 128r bytes in
 * length; the temporary space Y must also be the same size.
 */
static void
blockmix_salsa8(uint8_t * B, uint8_t * Y, size_t r)
{
    uint8_t X[64];
    size_t i;

    /* 1: X <-- B_{2r - 1} */
    blkcpy(X, &B[(2 * r - 1) * 64], 64);

    /* 2: for i = 0 to 2r - 1 do */
    for (i = 0; i < 2 * r; i++) {
        /* 3: X <-- H(X \xor B_i) */
        blkxor(X, &B[i * 64], 64);
        salsa20_8(X);

        /* 4: Y_i <-- X */
        blkcpy(&Y[i * 64], X, 64);
    }

    /* 6: B' <-- (Y_0, Y_2 ... Y_{2r-2}, Y_1, Y_3 ... Y_{2r-1}) */
    for (i = 0; i < r; i++)
        blkcpy(&B[i * 64], &Y[(i * 2) * 64], 64);
    for (i = 0; i < r; i++)
        blkcpy(&B[(i + r) * 64], &Y[(i * 2 + 1) * 64], 64);
}

/**
 * integerify(B, r):
 * Return the result of parsing B_{2r-1} as a little-endian integer.
 */
static uint64_t
integerify(uint8_t * B, size_t r)
{
    uint8_t * X = &B[(2 * r - 1) * 64];

    return (le64dec(X));
}

/**
 * smix(B, r, N, V, XY):
 * Compute B = SMix_r(B, N).  The input B must be 128r bytes in length; the
 * temporary storage V must be 128rN bytes in length; the temporary storage
 * XY must be 256r bytes in length.  The value N must be a power of 2.
 */
static void
smix(uint8_t * B, size_t r, uint64_t N, uint8_t * V, uint8_t * XY)
{
    uint8_t * X = XY;
    uint8_t * Y = &XY[128 * r];
    uint64_t i;
    uint64_t j;

    /* 1: X <-- B */
    blkcpy(X, B, 128 * r);

    /* 2: for i = 0 to N - 1 do */
    for (i = 0; i < N; i++) {
        /* 3: V_i <-- X */
        blkcpy(&V[i * (128 * r)], X, 128 * r);

        /* 4: X <-- H(X) */
        blockmix_salsa8(X, Y, r);
    }

    /* 6: for i = 0 to N - 1 do */
    for (i = 0; i < N; i++) {
        /* 7: j <-- Integerify(X) mod N */
        j = integerify(X, r) & (N - 1);

        /* 8: X <-- H(X \xor V_j) */
        blkxor(X, &V[j * (128 * r)], 128 * r);
        blockmix_salsa8(X, Y, r);
    }

    /* 10: B' <-- X */
    blkcpy(B, X, 128 * r);
}

/**
 * crypto_scrypt(passwd, passwdlen, salt, saltlen, N, r, p, buf, buflen):
 * Compute scrypt(passwd[0 .. passwdlen - 1], salt[0 .. saltlen - 1], N, r,
 * p, buflen) and write the result into buf.  The parameters r, p, and buflen
 * must satisfy r * p < 2^30 and buflen <= (2^32 - 1) * 32.  The parameter N
 * must be a power of 2.
 *
 * Return 0 on success; or -1 on error.
 */
int
libscrypt_scrypt(const uint8_t * passwd, size_t passwdlen,
    const uint8_t * salt, size_t saltlen, uint64_t N, uint32_t _r, uint32_t _p,
    uint8_t * buf, size_t buflen)
{
    uint8_t * B;
    uint8_t * V;
    uint8_t * XY;
    size_t r = _r, p = _p;
    uint32_t i;

    /* Sanity-check parameters. */
#if SIZE_MAX > UINT32_MAX
    if (buflen > (((uint64_t)(1) << 32) - 1) * 32) {
        errno = EFBIG;
        goto err0;
    }
#endif
    if ((uint64_t)(r) * (uint64_t)(p) >= (1 << 30)) {
        errno = EFBIG;
        goto err0;
    }
    if (((N & (N - 1)) != 0) || (N == 0)) {
        errno = EINVAL;
        goto err0;
    }
    if ((r > SIZE_MAX / 128 / p) ||
#if SIZE_MAX / 256 <= UINT32_MAX
        (r > SIZE_MAX / 256) ||
#endif
        (N > SIZE_MAX / 128 / r)) {
        errno = ENOMEM;
        goto err0;
    }

    /* Allocate memory. */
    if ((B = malloc(128 * r * p)) == NULL)
        goto err0;
    if ((XY = malloc(256 * r)) == NULL)
        goto err1;
    if ((V = malloc(128 * r * N)) == NULL)
        goto err2;

    /* 1: (B_0 ... B_{p-1}) <-- PBKDF2(P, S, 1, p * MFLen) */
    libscrypt_PBKDF2_SHA256(passwd, passwdlen, salt, saltlen, 1, B, p * 128 * r);

    /* 2: for i = 0 to p - 1 do */
    for (i = 0; i < p; i++) {
        /* 3: B_i <-- MF(B_i, N) */
        smix(&B[i * 128 * r], r, N, V, XY);
    }

    /* 5: DK <-- PBKDF2(P, B, 1, dkLen) */
    libscrypt_PBKDF2_SHA256(passwd, passwdlen, B, p * 128 * r, 1, buf, buflen);

    /* Free memory. */
    free(V);
    free(XY);
    free(B);

    /* Success! */
    return (0);

err2:
    free(XY);
err1:
    free(B);
err0:
    /* Failure! */
    return (-1);
}







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
 */

#include <sys/types.h>

#include <stdint.h>
#include <string.h>


/*
 * Encode a length len/4 vector of (uint32_t) into a length len vector of
 * (unsigned char) in big-endian form.  Assumes len is a multiple of 4.
 */
static void
be32enc_vect(unsigned char *dst, const uint32_t *src, size_t len)
{
    size_t i;

    for (i = 0; i < len / 4; i++)
        be32enc(dst + i * 4, src[i]);
}

/*
 * Decode a big-endian length len vector of (unsigned char) into a length
 * len/4 vector of (uint32_t).  Assumes len is a multiple of 4.
 */
static void
be32dec_vect(uint32_t *dst, const unsigned char *src, size_t len)
{
    size_t i;

    for (i = 0; i < len / 4; i++)
        dst[i] = be32dec(src + i * 4);
}

/* Elementary functions used by SHA256 */
#define Ch(x, y, z)    ((x & (y ^ z)) ^ z)
#define Maj(x, y, z)    ((x & (y | z)) | (y & z))
#define SHR(x, n)    (x >> n)
#define ROTR(x, n)    ((x >> n) | (x << (32 - n)))
#define S0(x)        (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define S1(x)        (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define s0(x)        (ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))
#define s1(x)        (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))

/* SHA256 round function */
#define RND(a, b, c, d, e, f, g, h, k)            \
    t0 = h + S1(e) + Ch(e, f, g) + k;        \
    t1 = S0(a) + Maj(a, b, c);            \
    d += t0;                    \
    h  = t0 + t1;

/* Adjusted round function for rotating state */
#define RNDr(S, W, i, k)            \
    RND(S[(64 - i) % 8], S[(65 - i) % 8],    \
        S[(66 - i) % 8], S[(67 - i) % 8],    \
        S[(68 - i) % 8], S[(69 - i) % 8],    \
        S[(70 - i) % 8], S[(71 - i) % 8],    \
        W[i] + k)

/*
 * SHA256 block compression function.  The 256-bit state is transformed via
 * the 512-bit input block to produce a new state.
 */
static void
SHA256_Transform(uint32_t * state, const unsigned char block[64])
{
    uint32_t W[64];
    uint32_t S[8];
    uint32_t t0, t1;
    int i;

    /* 1. Prepare message schedule W. */
    be32dec_vect(W, block, 64);
    for (i = 16; i < 64; i++)
        W[i] = s1(W[i - 2]) + W[i - 7] + s0(W[i - 15]) + W[i - 16];

    /* 2. Initialize working variables. */
    memcpy(S, state, 32);

    /* 3. Mix. */
    RNDr(S, W, 0, 0x428a2f98);
    RNDr(S, W, 1, 0x71374491);
    RNDr(S, W, 2, 0xb5c0fbcf);
    RNDr(S, W, 3, 0xe9b5dba5);
    RNDr(S, W, 4, 0x3956c25b);
    RNDr(S, W, 5, 0x59f111f1);
    RNDr(S, W, 6, 0x923f82a4);
    RNDr(S, W, 7, 0xab1c5ed5);
    RNDr(S, W, 8, 0xd807aa98);
    RNDr(S, W, 9, 0x12835b01);
    RNDr(S, W, 10, 0x243185be);
    RNDr(S, W, 11, 0x550c7dc3);
    RNDr(S, W, 12, 0x72be5d74);
    RNDr(S, W, 13, 0x80deb1fe);
    RNDr(S, W, 14, 0x9bdc06a7);
    RNDr(S, W, 15, 0xc19bf174);
    RNDr(S, W, 16, 0xe49b69c1);
    RNDr(S, W, 17, 0xefbe4786);
    RNDr(S, W, 18, 0x0fc19dc6);
    RNDr(S, W, 19, 0x240ca1cc);
    RNDr(S, W, 20, 0x2de92c6f);
    RNDr(S, W, 21, 0x4a7484aa);
    RNDr(S, W, 22, 0x5cb0a9dc);
    RNDr(S, W, 23, 0x76f988da);
    RNDr(S, W, 24, 0x983e5152);
    RNDr(S, W, 25, 0xa831c66d);
    RNDr(S, W, 26, 0xb00327c8);
    RNDr(S, W, 27, 0xbf597fc7);
    RNDr(S, W, 28, 0xc6e00bf3);
    RNDr(S, W, 29, 0xd5a79147);
    RNDr(S, W, 30, 0x06ca6351);
    RNDr(S, W, 31, 0x14292967);
    RNDr(S, W, 32, 0x27b70a85);
    RNDr(S, W, 33, 0x2e1b2138);
    RNDr(S, W, 34, 0x4d2c6dfc);
    RNDr(S, W, 35, 0x53380d13);
    RNDr(S, W, 36, 0x650a7354);
    RNDr(S, W, 37, 0x766a0abb);
    RNDr(S, W, 38, 0x81c2c92e);
    RNDr(S, W, 39, 0x92722c85);
    RNDr(S, W, 40, 0xa2bfe8a1);
    RNDr(S, W, 41, 0xa81a664b);
    RNDr(S, W, 42, 0xc24b8b70);
    RNDr(S, W, 43, 0xc76c51a3);
    RNDr(S, W, 44, 0xd192e819);
    RNDr(S, W, 45, 0xd6990624);
    RNDr(S, W, 46, 0xf40e3585);
    RNDr(S, W, 47, 0x106aa070);
    RNDr(S, W, 48, 0x19a4c116);
    RNDr(S, W, 49, 0x1e376c08);
    RNDr(S, W, 50, 0x2748774c);
    RNDr(S, W, 51, 0x34b0bcb5);
    RNDr(S, W, 52, 0x391c0cb3);
    RNDr(S, W, 53, 0x4ed8aa4a);
    RNDr(S, W, 54, 0x5b9cca4f);
    RNDr(S, W, 55, 0x682e6ff3);
    RNDr(S, W, 56, 0x748f82ee);
    RNDr(S, W, 57, 0x78a5636f);
    RNDr(S, W, 58, 0x84c87814);
    RNDr(S, W, 59, 0x8cc70208);
    RNDr(S, W, 60, 0x90befffa);
    RNDr(S, W, 61, 0xa4506ceb);
    RNDr(S, W, 62, 0xbef9a3f7);
    RNDr(S, W, 63, 0xc67178f2);

    /* 4. Mix local working variables into global state */
    for (i = 0; i < 8; i++)
        state[i] += S[i];

    /* Clean the stack. */
    memset(W, 0, 256);
    memset(S, 0, 32);
    t0 = t1 = 0;
}

static unsigned char PAD[64] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* Add padding and terminating bit-count. */
static void
SHA256_Pad(SHA256_CTX * ctx)
{
    unsigned char len[8];
    uint32_t r, plen;

    /*
     * Convert length to a vector of bytes -- we do this now rather
     * than later because the length will change after we pad.
     */
    be32enc_vect(len, ctx->count, 8);

    /* Add 1--64 bytes so that the resulting length is 56 mod 64 */
    r = (ctx->count[1] >> 3) & 0x3f;
    plen = (r < 56) ? (56 - r) : (120 - r);
    libscrypt_SHA256_Update(ctx, PAD, (size_t)plen);

    /* Add the terminating bit-count */
    libscrypt_SHA256_Update(ctx, len, 8);
}

/* SHA-256 initialization.  Begins a SHA-256 operation. */
void
libscrypt_SHA256_Init(SHA256_CTX * ctx)
{

    /* Zero bits processed so far */
    ctx->count[0] = ctx->count[1] = 0;

    /* Magic initialization constants */
    ctx->state[0] = 0x6A09E667;
    ctx->state[1] = 0xBB67AE85;
    ctx->state[2] = 0x3C6EF372;
    ctx->state[3] = 0xA54FF53A;
    ctx->state[4] = 0x510E527F;
    ctx->state[5] = 0x9B05688C;
    ctx->state[6] = 0x1F83D9AB;
    ctx->state[7] = 0x5BE0CD19;
}

/* Add bytes into the hash */
void
libscrypt_SHA256_Update(SHA256_CTX * ctx, const void *in, size_t len)
{
    uint32_t bitlen[2];
    uint32_t r;
    const unsigned char *src = in;

    /* Number of bytes left in the buffer from previous updates */
    r = (ctx->count[1] >> 3) & 0x3f;

    /* Convert the length into a number of bits */
    bitlen[1] = ((uint32_t)len) << 3;
    bitlen[0] = (uint32_t)(len >> 29);

    /* Update number of bits */
    if ((ctx->count[1] += bitlen[1]) < bitlen[1])
        ctx->count[0]++;
    ctx->count[0] += bitlen[0];

    /* Handle the case where we don't need to perform any transforms */
    if (len < 64 - r) {
        memcpy(&ctx->buf[r], src, len);
        return;
    }

    /* Finish the current block */
    memcpy(&ctx->buf[r], src, 64 - r);
    SHA256_Transform(ctx->state, ctx->buf);
    src += 64 - r;
    len -= 64 - r;

    /* Perform complete blocks */
    while (len >= 64) {
        SHA256_Transform(ctx->state, src);
        src += 64;
        len -= 64;
    }

    /* Copy left over data into buffer */
    memcpy(ctx->buf, src, len);
}

/*
 * SHA-256 finalization.  Pads the input data, exports the hash value,
 * and clears the context state.
 */
void
libscrypt_SHA256_Final(unsigned char digest[32], SHA256_CTX * ctx)
{

    /* Add padding */
    SHA256_Pad(ctx);

    /* Write the hash */
    be32enc_vect(digest, ctx->state, 32);

    /* Clear the context state */
    memset((void *)ctx, 0, sizeof(*ctx));
}

/* Initialize an HMAC-SHA256 operation with the given key. */
void
libscrypt_HMAC_SHA256_Init(HMAC_SHA256_CTX * ctx, const void * _K, size_t Klen)
{
    unsigned char pad[64];
    unsigned char khash[32];
    const unsigned char * K = _K;
    size_t i;

    /* If Klen > 64, the key is really SHA256(K). */
    if (Klen > 64) {
        libscrypt_SHA256_Init(&ctx->ictx);
        libscrypt_SHA256_Update(&ctx->ictx, K, Klen);
        libscrypt_SHA256_Final(khash, &ctx->ictx);
        K = khash;
        Klen = 32;
    }

    /* Inner SHA256 operation is SHA256(K xor [block of 0x36] || data). */
    libscrypt_SHA256_Init(&ctx->ictx);
    memset(pad, 0x36, 64);
    for (i = 0; i < Klen; i++)
        pad[i] ^= K[i];
    libscrypt_SHA256_Update(&ctx->ictx, pad, 64);

    /* Outer SHA256 operation is SHA256(K xor [block of 0x5c] || hash). */
    libscrypt_SHA256_Init(&ctx->octx);
    memset(pad, 0x5c, 64);
    for (i = 0; i < Klen; i++)
        pad[i] ^= K[i];
    libscrypt_SHA256_Update(&ctx->octx, pad, 64);

    /* Clean the stack. */
    memset(khash, 0, 32);
}

/* Add bytes to the HMAC-SHA256 operation. */
void
libscrypt_HMAC_SHA256_Update(HMAC_SHA256_CTX * ctx, const void *in, size_t len)
{

    /* Feed data to the inner SHA256 operation. */
    libscrypt_SHA256_Update(&ctx->ictx, in, len);
}

/* Finish an HMAC-SHA256 operation. */
void
libscrypt_HMAC_SHA256_Final(unsigned char digest[32], HMAC_SHA256_CTX * ctx)
{
    unsigned char ihash[32];

    /* Finish the inner SHA256 operation. */
    libscrypt_SHA256_Final(ihash, &ctx->ictx);

    /* Feed the inner hash to the outer SHA256 operation. */
    libscrypt_SHA256_Update(&ctx->octx, ihash, 32);

    /* Finish the outer SHA256 operation. */
    libscrypt_SHA256_Final(digest, &ctx->octx);

    /* Clean the stack. */
    memset(ihash, 0, 32);
}

/**
 * PBKDF2_SHA256(passwd, passwdlen, salt, saltlen, c, buf, dkLen):
 * Compute PBKDF2(passwd, salt, c, dkLen) using HMAC-SHA256 as the PRF, and
 * write the output to buf.  The value dkLen must be at most 32 * (2^32 - 1).
 */
void
libscrypt_PBKDF2_SHA256(const uint8_t * passwd, size_t passwdlen, const uint8_t * salt,
    size_t saltlen, uint64_t c, uint8_t * buf, size_t dkLen)
{
    HMAC_SHA256_CTX PShctx, hctx;
    size_t i;
    uint8_t ivec[4];
    uint8_t U[32];
    uint8_t T[32];
    uint64_t j;
    int k;
    size_t clen;

    /* Compute HMAC state after processing P and S. */
    libscrypt_HMAC_SHA256_Init(&PShctx, passwd, passwdlen);
    libscrypt_HMAC_SHA256_Update(&PShctx, salt, saltlen);

    /* Iterate through the blocks. */
    for (i = 0; i * 32 < dkLen; i++) {
        /* Generate INT(i + 1). */
        be32enc(ivec, (uint32_t)(i + 1));

        /* Compute U_1 = PRF(P, S || INT(i)). */
        memcpy(&hctx, &PShctx, sizeof(HMAC_SHA256_CTX));
        libscrypt_HMAC_SHA256_Update(&hctx, ivec, 4);
        libscrypt_HMAC_SHA256_Final(U, &hctx);

        /* T_i = U_1 ... */
        memcpy(T, U, 32);

        for (j = 2; j <= c; j++) {
            /* Compute U_j. */
            libscrypt_HMAC_SHA256_Init(&hctx, passwd, passwdlen);
            libscrypt_HMAC_SHA256_Update(&hctx, U, 32);
            libscrypt_HMAC_SHA256_Final(U, &hctx);

            /* ... xor U_j ... */
            for (k = 0; k < 32; k++)
                T[k] ^= U[k];
        }

        /* Copy as many bytes as necessary into buf. */
        clen = dkLen - i * 32;
        if (clen > 32)
            clen = 32;
        memcpy(&buf[i * 32], T, clen);
    }

    /* Clean PShctx, since we never called _Final on it. */
    memset(&PShctx, 0, sizeof(HMAC_SHA256_CTX));
}






#include <string.h>

/* Implements a constant time version of strcmp()
 * Will return 1 if a and b are equal, 0 if they are not */
int slow_equals(const char* a, const char* b)
{
    size_t lena, lenb, diff, i;
    lena = strlen(a);
    lenb = strlen(b);
    diff = strlen(a) ^ strlen(b);

    for(i=0; i<lena && i<lenb; i++)
    {
        diff |= a[i] ^ b[i];
    }
    if (diff == 0)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}
















