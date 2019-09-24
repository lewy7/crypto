#include <stdio.h>
#include <string.h>
#include "crypto_md5.h"
#include "crypto_sha1.h"
#include "crypto_base64.h"
#include "crypto_aes256cbc.h"

int main()
{
	//1.1 md5
	CRYPTO_MD5_CTX ctx;
	unsigned char result[16];
	unsigned char str[36];
	//C:>printf "000000" | openssl dgst -md5 
	CRYPTO_MD5_Init(&ctx);
	CRYPTO_MD5_Update(&ctx, "000", 3);
	CRYPTO_MD5_Update(&ctx, "000", 3);
	CRYPTO_MD5_Final(result, &ctx);
	CRYPTO_MD5_ToString(str,result);
	printf("MD5 %s\n",str);

	//C:>openssl dgst -md5 C:\openssl-0.9.8zh\crypto\md5\md5.c 
	CRYPTO_MD5_File(result,"md5_257481c6c06867578dea1e990f761a19.c");
	CRYPTO_MD5_ToString(str,result);
	printf("file MD5 %s\n",str);

	//1.2 sha1
	CRYPTO_SHA1_CTX ctx_sha1;
	unsigned char result_sha1[20];
	unsigned char str_sha1[48];

	//C:>printf "000000" | openssl dgst -sha1 
	CRYPTO_SHA1_Init(&ctx_sha1);
	CRYPTO_SHA1_Update(&ctx_sha1, "000", 3);
	CRYPTO_SHA1_Update(&ctx_sha1, "000", 3);
	CRYPTO_SHA1_Final(result_sha1, &ctx_sha1);
	CRYPTO_SHA1_ToString(str_sha1,result_sha1);
	printf("SHA1 %s\n",str_sha1);

	//C:>openssl dgst -sha1 C:\openssl-0.9.8zh\crypto\sha\sha1.c
	CRYPTO_SHA1_File(result_sha1,"sha1_c42a72b89405a11683c696d217154f69a1131698.c");
	CRYPTO_SHA1_ToString(str_sha1,result_sha1);
	printf("file SHA1 %s\n",str_sha1);

	//1.3 base64
	//C:>printf "000000"|openssl base64
	unsigned char source[]="000000,:,%,\\,\t,+,=,>,?,   ,76,76,76,76,76,76,76,76,76,76,76,76,76,76,76,76,76,76,76";
	size_t source_len = strlen((char *)source);
	unsigned char result_base64[128];
	size_t result_len;
	
	CRYPTO_BASE64_Encode(result_base64,&result_len,source,source_len);
	result_base64[result_len]='\0';
	printf("base64 encode[%d] %s\n",result_len,result_base64);

	memset(source,0,source_len);source_len=0;
	CRYPTO_BASE64_Decode(source,&source_len,result_base64,result_len);
	printf("base64 decode[%d] %s\n",source_len,source);



	CRYPTO_BASE64URL_Encode(result_base64,&result_len,source,source_len);
	result_base64[result_len]='\0';
	printf("base64url encode[%d] %s\n",result_len,result_base64);
	memset(source,0,source_len);source_len=0;
	CRYPTO_BASE64URL_Decode(source,&source_len,result_base64,result_len);
	printf("base64url decode[%d] %s\n",source_len,source);

	//1.4 aes-256-cbc
	//C:>printf "000000"|openssl enc -aes-256-cbc 

	unsigned char iv[16]  = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
	unsigned char key[32] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
		0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };//256 bit
    
	//data length must be : length % 16 == 0 and less than 4G Bytes
	unsigned char data[64] = {0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5, 0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28, 
		0xf4, 0x43, 0xe3, 0xca, 0x4d, 0x62, 0xb5, 0x9a, 0xca, 0x84, 0xe9, 0x90, 0xca, 0xca, 0xf5, 0xc5, 
		0x2b, 0x09, 0x30, 0xda, 0xa2, 0x3d, 0xe9, 0x4c, 0xe8, 0x70, 0x17, 0xba, 0x2d, 0x84, 0x98, 0x8d, 
		0xdf, 0xc9, 0xc5, 0x8d, 0xb6, 0x7a, 0xad, 0xa6, 0x13, 0xc2, 0xdd, 0x08, 0x45, 0x79, 0x41, 0xa6 };
	unsigned char hex_dump[160];
	memset(hex_dump,0,sizeof(hex_dump));
	memcpy(hex_dump,data,64);
	CRYPTO_AES256CBC_hex_dump(hex_dump,data,64);
	printf("aes-256-cbc before encrypt [%s]\n",hex_dump);

	CRYPTO_AES256CBC_CTX ctx_aes256cbc;
	CRYPTO_AES256CBC_init_ctx_iv(&ctx_aes256cbc, key, iv);
	CRYPTO_AES256CBC_encrypt(&ctx_aes256cbc, data, 64);
	
	memset(hex_dump,0,sizeof(hex_dump));
	memcpy(hex_dump,data,64);
	CRYPTO_AES256CBC_hex_dump(hex_dump,data,64);
	printf("aes-256-cbc after encrypt [%s]\n",hex_dump);

	
	//must re-initiate after use key and iv 
	CRYPTO_AES256CBC_init_ctx_iv(&ctx_aes256cbc, key, iv);
	CRYPTO_AES256CBC_decrypt(&ctx_aes256cbc, data, 64);


	memset(hex_dump,0,sizeof(hex_dump));
	memcpy(hex_dump,data,64);
	CRYPTO_AES256CBC_hex_dump(hex_dump,data,64);
	printf("aes-256-cbc after decrypt [%s]\n",hex_dump);
	
	void CRYPTO_AES256CTR_crypt(CRYPTO_AES256CBC_CTX* ctx, unsigned char* buf, unsigned  int length);
	return 0;
}
