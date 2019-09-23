//based on  http://nginx.org/

#ifndef _CRYPTO_BASE64_H_
#define _CRYPTO_BASE64_H_

void CRYPTO_BASE64_Encode(unsigned char *dst,  size_t *dst_len, unsigned char *src, size_t src_len);
int CRYPTO_BASE64_Decode(unsigned char *dst,  size_t *dst_len, unsigned char *src, size_t src_len);

void CRYPTO_BASE64URL_Encode(unsigned char *dst,  size_t *dst_len, unsigned char *src, size_t src_len);
int CRYPTO_BASE64URL_Decode(unsigned char *dst,  size_t *dst_len, unsigned char *src, size_t src_len);

#endif