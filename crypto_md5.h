/*
 * This is an OpenSSL-compatible implementation of the RSA Data Security, Inc.
 * MD5 Message-Digest Algorithm (RFC 1321).
 *
 * Homepage:
 * http://openwall.info/wiki/people/solar/software/public-domain-source-code/md5
 *
 * Author:
 * Alexander Peslyak, better known as Solar Designer <solar at openwall.com>
 *
 * This software was written by Alexander Peslyak in 2001.  No copyright is
 * claimed, and the software is hereby placed in the public domain.
 * In case this attempt to disclaim copyright and place the software in the
 * public domain is deemed null and void, then the software is
 * Copyright (c) 2001 Alexander Peslyak and it is hereby released to the
 * general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 * See md5.c for more information.
 */

#ifndef _CRYPTO_MD5_H_
#define _CRYPTO_MD5_H_


typedef struct {
	unsigned int lo, hi;
	unsigned int a, b, c, d;
	unsigned char buffer[64];
	unsigned int block[16];
} CRYPTO_MD5_CTX;

void CRYPTO_MD5_Init(CRYPTO_MD5_CTX *ctx);
void CRYPTO_MD5_Update(CRYPTO_MD5_CTX *ctx, const void *data, unsigned long size);
void CRYPTO_MD5_Final(unsigned char *result, CRYPTO_MD5_CTX *ctx);
int  CRYPTO_MD5_File(unsigned char *result,char *file);
//str_out will add '\0' at the end
unsigned char *CRYPTO_MD5_ToString(unsigned char *str_out,unsigned char *md5_in);

#endif