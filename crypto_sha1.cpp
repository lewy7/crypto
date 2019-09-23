#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include "crypto_sha1.h"

static const unsigned char *CRYPTO_SHA1_body(CRYPTO_SHA1_CTX *ctx, const unsigned char *data,
    size_t size);


void
CRYPTO_SHA1_Init(CRYPTO_SHA1_CTX *ctx)
{
    ctx->a = 0x67452301;
    ctx->b = 0xefcdab89;
    ctx->c = 0x98badcfe;
    ctx->d = 0x10325476;
    ctx->e = 0xc3d2e1f0;

    ctx->bytes = 0;
}


void
CRYPTO_SHA1_Update(CRYPTO_SHA1_CTX *ctx, const void *data, size_t size)
{
    size_t  used, free;

    used = (size_t) (ctx->bytes & 0x3f);
    ctx->bytes += size;

    if (used) {
        free = 64 - used;

        if (size < free) {
            memcpy(&ctx->buffer[used], data, size);
            return;
        }

        memcpy(&ctx->buffer[used], data, free);
        data = (unsigned char *) data + free;
        size -= free;
        (void) CRYPTO_SHA1_body(ctx, ctx->buffer, 64);
    }

    if (size >= 64) {
        data = CRYPTO_SHA1_body(ctx, (unsigned char *)data, size & ~(size_t) 0x3f);
        size &= 0x3f;
    }

    memcpy(ctx->buffer, data, size);
}


void
CRYPTO_SHA1_Final(unsigned char result[20], CRYPTO_SHA1_CTX *ctx)
{
    size_t  used, free;

    used = (size_t) (ctx->bytes & 0x3f);

    ctx->buffer[used++] = 0x80;

    free = 64 - used;

    if (free < 8) {
        memset(&ctx->buffer[used], 0, free);
        (void) CRYPTO_SHA1_body(ctx, ctx->buffer, 64);
        used = 0;
        free = 64;
    }

    memset(&ctx->buffer[used], 0, free - 8);

    ctx->bytes <<= 3;
    ctx->buffer[56] = (unsigned char) (ctx->bytes >> 56);
    ctx->buffer[57] = (unsigned char) (ctx->bytes >> 48);
    ctx->buffer[58] = (unsigned char) (ctx->bytes >> 40);
    ctx->buffer[59] = (unsigned char) (ctx->bytes >> 32);
    ctx->buffer[60] = (unsigned char) (ctx->bytes >> 24);
    ctx->buffer[61] = (unsigned char) (ctx->bytes >> 16);
    ctx->buffer[62] = (unsigned char) (ctx->bytes >> 8);
    ctx->buffer[63] = (unsigned char) ctx->bytes;

    (void) CRYPTO_SHA1_body(ctx, ctx->buffer, 64);

    result[0] = (unsigned char) (ctx->a >> 24);
    result[1] = (unsigned char) (ctx->a >> 16);
    result[2] = (unsigned char) (ctx->a >> 8);
    result[3] = (unsigned char) ctx->a;
    result[4] = (unsigned char) (ctx->b >> 24);
    result[5] = (unsigned char) (ctx->b >> 16);
    result[6] = (unsigned char) (ctx->b >> 8);
    result[7] = (unsigned char) ctx->b;
    result[8] = (unsigned char) (ctx->c >> 24);
    result[9] = (unsigned char) (ctx->c >> 16);
    result[10] = (unsigned char) (ctx->c >> 8);
    result[11] = (unsigned char) ctx->c;
    result[12] = (unsigned char) (ctx->d >> 24);
    result[13] = (unsigned char) (ctx->d >> 16);
    result[14] = (unsigned char) (ctx->d >> 8);
    result[15] = (unsigned char) ctx->d;
    result[16] = (unsigned char) (ctx->e >> 24);
    result[17] = (unsigned char) (ctx->e >> 16);
    result[18] = (unsigned char) (ctx->e >> 8);
    result[19] = (unsigned char) ctx->e;

    memset(ctx, 0, sizeof(*ctx));
}


/*
 * Helper functions.
 */

#define ROTATE(bits, word)  (((word) << (bits)) | ((word) >> (32 - (bits))))

#define F1(b, c, d)  (((b) & (c)) | ((~(b)) & (d)))
#define F2(b, c, d)  ((b) ^ (c) ^ (d))
#define F3(b, c, d)  (((b) & (c)) | ((b) & (d)) | ((c) & (d)))

#define STEP(f, a, b, c, d, e, w, t)                                          \
    temp = ROTATE(5, (a)) + f((b), (c), (d)) + (e) + (w) + (t);               \
    (e) = (d);                                                                \
    (d) = (c);                                                                \
    (c) = ROTATE(30, (b));                                                    \
    (b) = (a);                                                                \
    (a) = temp;


/*
 * GET() reads 4 input bytes in big-endian byte order and returns
 * them as unsigned int.
 */

#define GET(n)                                                                \
    ((unsigned int) p[n * 4 + 3] |                                                \
    ((unsigned int) p[n * 4 + 2] << 8) |                                          \
    ((unsigned int) p[n * 4 + 1] << 16) |                                         \
    ((unsigned int) p[n * 4] << 24))


/*
 * This processes one or more 64-byte data blocks, but does not update
 * the bit counters.  There are no alignment requirements.
 */

static const unsigned char *
CRYPTO_SHA1_body(CRYPTO_SHA1_CTX *ctx, const unsigned char *data, size_t size)
{
    unsigned int       a, b, c, d, e, temp;
    unsigned int       saved_a, saved_b, saved_c, saved_d, saved_e;
    unsigned int       words[80];
    unsigned int     i;
    const unsigned char  *p;

    p = data;

    a = ctx->a;
    b = ctx->b;
    c = ctx->c;
    d = ctx->d;
    e = ctx->e;

    do {
        saved_a = a;
        saved_b = b;
        saved_c = c;
        saved_d = d;
        saved_e = e;

        /* Load data block into the words array */

        for (i = 0; i < 16; i++) {
            words[i] = GET(i);
        }

        for (i = 16; i < 80; i++) {
            words[i] = ROTATE(1, words[i - 3] ^ words[i - 8] ^ words[i - 14]
                                 ^ words[i - 16]);
        }

        /* Transformations */

        STEP(F1, a, b, c, d, e, words[0],  0x5a827999);
        STEP(F1, a, b, c, d, e, words[1],  0x5a827999);
        STEP(F1, a, b, c, d, e, words[2],  0x5a827999);
        STEP(F1, a, b, c, d, e, words[3],  0x5a827999);
        STEP(F1, a, b, c, d, e, words[4],  0x5a827999);
        STEP(F1, a, b, c, d, e, words[5],  0x5a827999);
        STEP(F1, a, b, c, d, e, words[6],  0x5a827999);
        STEP(F1, a, b, c, d, e, words[7],  0x5a827999);
        STEP(F1, a, b, c, d, e, words[8],  0x5a827999);
        STEP(F1, a, b, c, d, e, words[9],  0x5a827999);
        STEP(F1, a, b, c, d, e, words[10], 0x5a827999);
        STEP(F1, a, b, c, d, e, words[11], 0x5a827999);
        STEP(F1, a, b, c, d, e, words[12], 0x5a827999);
        STEP(F1, a, b, c, d, e, words[13], 0x5a827999);
        STEP(F1, a, b, c, d, e, words[14], 0x5a827999);
        STEP(F1, a, b, c, d, e, words[15], 0x5a827999);
        STEP(F1, a, b, c, d, e, words[16], 0x5a827999);
        STEP(F1, a, b, c, d, e, words[17], 0x5a827999);
        STEP(F1, a, b, c, d, e, words[18], 0x5a827999);
        STEP(F1, a, b, c, d, e, words[19], 0x5a827999);

        STEP(F2, a, b, c, d, e, words[20], 0x6ed9eba1);
        STEP(F2, a, b, c, d, e, words[21], 0x6ed9eba1);
        STEP(F2, a, b, c, d, e, words[22], 0x6ed9eba1);
        STEP(F2, a, b, c, d, e, words[23], 0x6ed9eba1);
        STEP(F2, a, b, c, d, e, words[24], 0x6ed9eba1);
        STEP(F2, a, b, c, d, e, words[25], 0x6ed9eba1);
        STEP(F2, a, b, c, d, e, words[26], 0x6ed9eba1);
        STEP(F2, a, b, c, d, e, words[27], 0x6ed9eba1);
        STEP(F2, a, b, c, d, e, words[28], 0x6ed9eba1);
        STEP(F2, a, b, c, d, e, words[29], 0x6ed9eba1);
        STEP(F2, a, b, c, d, e, words[30], 0x6ed9eba1);
        STEP(F2, a, b, c, d, e, words[31], 0x6ed9eba1);
        STEP(F2, a, b, c, d, e, words[32], 0x6ed9eba1);
        STEP(F2, a, b, c, d, e, words[33], 0x6ed9eba1);
        STEP(F2, a, b, c, d, e, words[34], 0x6ed9eba1);
        STEP(F2, a, b, c, d, e, words[35], 0x6ed9eba1);
        STEP(F2, a, b, c, d, e, words[36], 0x6ed9eba1);
        STEP(F2, a, b, c, d, e, words[37], 0x6ed9eba1);
        STEP(F2, a, b, c, d, e, words[38], 0x6ed9eba1);
        STEP(F2, a, b, c, d, e, words[39], 0x6ed9eba1);

        STEP(F3, a, b, c, d, e, words[40], 0x8f1bbcdc);
        STEP(F3, a, b, c, d, e, words[41], 0x8f1bbcdc);
        STEP(F3, a, b, c, d, e, words[42], 0x8f1bbcdc);
        STEP(F3, a, b, c, d, e, words[43], 0x8f1bbcdc);
        STEP(F3, a, b, c, d, e, words[44], 0x8f1bbcdc);
        STEP(F3, a, b, c, d, e, words[45], 0x8f1bbcdc);
        STEP(F3, a, b, c, d, e, words[46], 0x8f1bbcdc);
        STEP(F3, a, b, c, d, e, words[47], 0x8f1bbcdc);
        STEP(F3, a, b, c, d, e, words[48], 0x8f1bbcdc);
        STEP(F3, a, b, c, d, e, words[49], 0x8f1bbcdc);
        STEP(F3, a, b, c, d, e, words[50], 0x8f1bbcdc);
        STEP(F3, a, b, c, d, e, words[51], 0x8f1bbcdc);
        STEP(F3, a, b, c, d, e, words[52], 0x8f1bbcdc);
        STEP(F3, a, b, c, d, e, words[53], 0x8f1bbcdc);
        STEP(F3, a, b, c, d, e, words[54], 0x8f1bbcdc);
        STEP(F3, a, b, c, d, e, words[55], 0x8f1bbcdc);
        STEP(F3, a, b, c, d, e, words[56], 0x8f1bbcdc);
        STEP(F3, a, b, c, d, e, words[57], 0x8f1bbcdc);
        STEP(F3, a, b, c, d, e, words[58], 0x8f1bbcdc);
        STEP(F3, a, b, c, d, e, words[59], 0x8f1bbcdc);

        STEP(F2, a, b, c, d, e, words[60], 0xca62c1d6);
        STEP(F2, a, b, c, d, e, words[61], 0xca62c1d6);
        STEP(F2, a, b, c, d, e, words[62], 0xca62c1d6);
        STEP(F2, a, b, c, d, e, words[63], 0xca62c1d6);
        STEP(F2, a, b, c, d, e, words[64], 0xca62c1d6);
        STEP(F2, a, b, c, d, e, words[65], 0xca62c1d6);
        STEP(F2, a, b, c, d, e, words[66], 0xca62c1d6);
        STEP(F2, a, b, c, d, e, words[67], 0xca62c1d6);
        STEP(F2, a, b, c, d, e, words[68], 0xca62c1d6);
        STEP(F2, a, b, c, d, e, words[69], 0xca62c1d6);
        STEP(F2, a, b, c, d, e, words[70], 0xca62c1d6);
        STEP(F2, a, b, c, d, e, words[71], 0xca62c1d6);
        STEP(F2, a, b, c, d, e, words[72], 0xca62c1d6);
        STEP(F2, a, b, c, d, e, words[73], 0xca62c1d6);
        STEP(F2, a, b, c, d, e, words[74], 0xca62c1d6);
        STEP(F2, a, b, c, d, e, words[75], 0xca62c1d6);
        STEP(F2, a, b, c, d, e, words[76], 0xca62c1d6);
        STEP(F2, a, b, c, d, e, words[77], 0xca62c1d6);
        STEP(F2, a, b, c, d, e, words[78], 0xca62c1d6);
        STEP(F2, a, b, c, d, e, words[79], 0xca62c1d6);

        a += saved_a;
        b += saved_b;
        c += saved_c;
        d += saved_d;
        e += saved_e;

        p += 64;

    } while (size -= 64);

    ctx->a = a;
    ctx->b = b;
    ctx->c = c;
    ctx->d = d;
    ctx->e = e;

    return p;
}

unsigned char *CRYPTO_SHA1_ToString(unsigned char *str_out,unsigned char *md5_in)
{
    static unsigned char  hex[] = "0123456789abcdef";
	int len = 20;
    while (len--) {
        *str_out++ = hex[*md5_in >> 4];
        *str_out++ = hex[*md5_in++ & 0xf];
    }
	*str_out = '\0';
    return str_out;
}


int CRYPTO_SHA1_File(unsigned char *result,char *file)
{
	FILE *fp;
	int n;
	unsigned char *buffer;
	
	memset(result,0,20);
	buffer=(unsigned char *)malloc(4096);
	if(buffer==NULL)
		return -1;
	
	fp = fopen(file,"rb");
	if(fp==NULL){
		free(buffer);
		return -1;
	}
	
	CRYPTO_SHA1_CTX ctx;
	CRYPTO_SHA1_Init(&ctx);
	
	while ((n = fread(buffer, 1, 4096, fp))>0)
	{
		CRYPTO_SHA1_Update(&ctx, buffer, n);
	}
	
	CRYPTO_SHA1_Final(result, &ctx);
	
	free(buffer);
	fclose(fp);
	return 0;
}

