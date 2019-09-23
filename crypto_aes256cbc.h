//base on https://github.com/kokke/tiny-AES-c

#ifndef _CRYPTO_AES256CBC_H_
#define _CRYPTO_AES256CBC_H_

#define AES_BLOCKLEN 16
#define AES_KEYLEN 32
#define AES_keyExpSize 240


typedef struct {
	unsigned char RoundKey[AES_keyExpSize];
	unsigned char Iv[AES_BLOCKLEN];
} CRYPTO_AES256CBC_CTX;

void CRYPTO_AES256CBC_init_ctx_iv(CRYPTO_AES256CBC_CTX* ctx, const unsigned char* key, const unsigned char* iv);

void CRYPTO_AES256CBC_encrypt(CRYPTO_AES256CBC_CTX* ctx, unsigned char* buf, unsigned  int length);
void CRYPTO_AES256CBC_decrypt(CRYPTO_AES256CBC_CTX* ctx, unsigned char* buf, unsigned  int length);
unsigned char *CRYPTO_AES256CBC_hex_dump(unsigned char *dst, unsigned char *src, size_t len);

#endif
