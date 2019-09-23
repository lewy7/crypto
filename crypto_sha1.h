//based on  http://nginx.org/

#ifndef _CRYPTO_SHA1_H_
#define _CRYPTO_SHA1_H_


typedef struct {
#ifdef _WIN32
    unsigned __int64  bytes;
#else
	unsigned long long int bytes;
#endif

	unsigned int a, b, c, d, e, f;
    unsigned char buffer[64];
} CRYPTO_SHA1_CTX;

void CRYPTO_SHA1_Init(CRYPTO_SHA1_CTX *ctx);
void CRYPTO_SHA1_Update(CRYPTO_SHA1_CTX *ctx, const void *data, size_t size);
void CRYPTO_SHA1_Final(unsigned char *result, CRYPTO_SHA1_CTX *ctx);
int  CRYPTO_SHA1_File(unsigned char *result,char *file);
//str_out will add '\0' at the end
unsigned char *CRYPTO_SHA1_ToString(unsigned char *str_out,unsigned char *sha1_in);


#endif