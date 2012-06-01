/*
**	Copyright (C) 2011 Politecnico di Torino, Italy
**
**		TORSEC group -- http://security.polito.it
**		Author: Paolo Smiraglia <paolo.smiraglia@polito.it>
**
**	This file is part of Libsklog.
**
**	Libsklog is free software: you can redistribute it and/or modify
**	it under the terms of the GNU General Public License as published by
**	the Free Software Foundation; either version 2 of the License, or
**	(at your option) any later version.
**
**	Libsklog is distributed in the hope that it will be useful,
**	but WITHOUT ANY WARRANTY; without even the implied warranty of
**	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**	GNU General Public License for more details.
**
**	You should have received a copy of the GNU General Public License
**	along with Libsklog.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "sklog_internal.h"

#include <string.h>

#include <arpa/inet.h>

#include <netinet/in.h>

#include <openssl/aes.h>
#include <openssl/engine.h>
#include <openssl/err.h>

/*--------------------------------------------------------------------*/
/*						 crypto primitives						  */
/*--------------------------------------------------------------------*/

SKLOG_RETURN
sign_message(unsigned char *message, unsigned int message_len,
			 EVP_PKEY *signing_key, unsigned char **signature,
			 unsigned int *signature_len)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	int retval = 0;

	EVP_PKEY_CTX *ctx = 0;
	unsigned char md[SHA256_LEN] = { 0 };
	unsigned char *sig = 0;
	size_t md_len = SHA256_LEN;
	size_t sig_len = 0;
	EVP_MD_CTX mdctx;

	OpenSSL_add_all_digests();
	ERR_load_crypto_strings();

	//~ generate sha256 message digest
	
	EVP_MD_CTX_init(&mdctx);

	retval = EVP_DigestInit_ex(&mdctx,EVP_sha256(),NULL);
	if ( retval == 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}
	
	retval = EVP_DigestUpdate(&mdctx,message,message_len);
	if ( retval == 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}
	
	retval = EVP_DigestFinal_ex(&mdctx,md,(unsigned int *)&md_len);
	if ( retval == 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}
	
	EVP_MD_CTX_cleanup(&mdctx);

	/*
	 * assumes signing_key, md and mdlen are already set up and that
	 * signing_key is an RSA private key
	 */

	//~ why second argument is NULL? To investigate...
	ctx = EVP_PKEY_CTX_new(signing_key,NULL);

	if ( ctx == NULL ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	if ( EVP_PKEY_sign_init(ctx) <= 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	if ( EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0 ) {
	   ERR_print_errors_fp(stderr);
	   goto error;
	}

	if ( EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0 ) {
	   ERR_print_errors_fp(stderr);
	   goto error;
	}

	//~ determine buffer length
	if ( EVP_PKEY_sign(ctx, NULL, &sig_len, md, md_len) <= 0 ) {
	   ERR_print_errors_fp(stderr);
	   goto error;
	}

	if ( SKLOG_alloc(&sig,unsigned char,sig_len) == SKLOG_FAILURE ) {
		ERROR("SKLOG_alloc() failure");
		goto error;
	}

	if ( EVP_PKEY_sign(ctx, sig, &sig_len, md, md_len) <= 0 ) {
	   ERR_print_errors_fp(stderr);
	   goto error;
	}

	/* Signature is sig_len bytes written to buffer sig */
	if ( SKLOG_alloc(signature,unsigned char,sig_len) == SKLOG_FAILURE ) {
		ERROR("SKLOG_alloc() failure");
		goto error;
	}

	memcpy(*signature,sig,sig_len);
	*signature_len = sig_len;

	SKLOG_free(&sig);
	EVP_PKEY_CTX_free(ctx);
	ERR_free_strings();

	#ifdef HAVE_NOTIFY
	NOTIFY("signature process successful")
	#endif

	return SKLOG_SUCCESS;

error:
	if ( sig > 0 ) SKLOG_free(sig);
	if ( ctx > 0 ) EVP_PKEY_CTX_free(ctx);
	ERR_free_strings();
	return SKLOG_FAILURE;
}

SKLOG_RETURN
sign_verify(EVP_PKEY *verify_key, unsigned char	*signature,
			size_t signature_len, unsigned char	*message,\
			unsigned int message_len)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	int retval = 0;
	
	unsigned char md[SHA256_LEN] = { 0 };
	unsigned int md_len = 0;
	EVP_MD_CTX mdctx;

	EVP_PKEY_CTX *ctx = NULL;

	OpenSSL_add_all_digests();
	ERR_load_crypto_strings();
	
	//~ generate sha256 message digest
	EVP_MD_CTX_init(&mdctx);
	
	retval = EVP_DigestInit_ex(&mdctx,EVP_sha256(),NULL);
	if ( retval == 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}
	
	retval = EVP_DigestUpdate(&mdctx,message,message_len);
	if ( retval == 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}
	
	retval = EVP_DigestFinal_ex(&mdctx,md,&md_len);
	if ( retval == 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}
	
	EVP_MD_CTX_cleanup(&mdctx);

	//~ verify signature
	if ( (ctx = EVP_PKEY_CTX_new(verify_key,NULL)) == NULL ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	if ( EVP_PKEY_verify_init(ctx) <= 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	if ( EVP_PKEY_CTX_set_rsa_padding(ctx,RSA_PKCS1_PADDING) <= 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	if ( EVP_PKEY_CTX_set_signature_md(ctx,EVP_sha256()) <= 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	retval = EVP_PKEY_verify(ctx,signature,signature_len,md,md_len);

	if ( retval < 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	if ( retval > 0 ) {
		#ifdef DO_TRACE
		NOTIFY("signature verification successfull :-D");
		#endif
		ERR_free_strings();
		return SKLOG_SUCCESS;
	} else {
		NOTIFY("signature verification fails :-(")
	}

error:
	ERR_free_strings();
	return SKLOG_FAILURE;
}

SKLOG_RETURN
pke_encrypt(X509 *cert, unsigned char *in, unsigned char in_len,
			unsigned char **out, size_t	*out_len)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	int retval = 0;

	EVP_PKEY *pubkey = 0;
	EVP_PKEY_CTX *evp_ctx = 0;

	OpenSSL_add_all_digests();
	ERR_load_crypto_strings();

	if ( (pubkey = X509_get_pubkey(cert)) == NULL ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	if ( (evp_ctx = EVP_PKEY_CTX_new(pubkey,NULL)) == NULL ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	retval = EVP_PKEY_encrypt_init(evp_ctx);

	if ( retval <= 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	retval = EVP_PKEY_CTX_set_rsa_padding(evp_ctx,RSA_PKCS1_PADDING);

	if ( retval <= 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	retval = EVP_PKEY_encrypt(evp_ctx,NULL,out_len,in,in_len);

	if ( retval <= 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	if ( (*out = OPENSSL_malloc(*out_len)) == NULL ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	retval = EVP_PKEY_encrypt(evp_ctx,*out,out_len,in,in_len);

	if ( retval <= 0 )  {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	EVP_PKEY_CTX_free(evp_ctx);
	ERR_free_strings();
	return SKLOG_SUCCESS;

error:
	if ( evp_ctx > 0 ) EVP_PKEY_CTX_free(evp_ctx);
	if ( *out > 0 ) OPENSSL_free(*out);
	ERR_free_strings();
	return SKLOG_FAILURE;
}

SKLOG_RETURN
pke_decrypt(EVP_PKEY *key, unsigned char *in, size_t in_len,
			unsigned char **out, size_t *out_len)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	int retval = 0;
	
	EVP_PKEY_CTX *ctx = NULL;

	OpenSSL_add_all_digests();
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	/*
	 * assumes key in, inlen are already set up and that key is an RSA
	 * private key
	 */

	if ( (ctx = EVP_PKEY_CTX_new(key,NULL)) == NULL ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	retval = EVP_PKEY_decrypt_init(ctx);

	if ( retval <= 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	retval = EVP_PKEY_CTX_set_rsa_padding(ctx,RSA_PKCS1_PADDING);

	if ( retval <= 0 ) {
		WARNING("EVP_PKEY_CTX_set_rsa_padding")
		ERR_print_errors_fp(stderr);
		goto error;
	}

	/* Determine buffer length */

	retval = EVP_PKEY_decrypt(ctx, NULL, out_len, in, in_len);


	if ( retval <= 0 ) {
		WARNING("EVP_PKEY_decrypt 1")
		if ( retval == -2 )
			WARNING("unsupported")
		ERR_print_errors_fp(stderr);
		goto error;
	}

	if ( (*out = OPENSSL_malloc(*out_len)) == NULL ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	retval = EVP_PKEY_decrypt(ctx, *out, out_len, in, in_len);

	if ( retval <= 0 ) {
		WARNING("EVP_PKEY_decrypt 2")
		if ( retval == -2 )
			WARNING("unsupported")
		SKLOG_free(out);
		ERR_print_errors_fp(stderr);
		goto error;
	}

	/* Decrypted data is outlen bytes written to buffer out */

	ERR_free_strings();
	return SKLOG_SUCCESS;

error:
	if ( ctx > 0 ) EVP_PKEY_CTX_free(ctx);
	ERR_free_strings();
	return SKLOG_FAILURE;
}

SKLOG_RETURN
aes256_encrypt(unsigned char *plain, unsigned int plain_len,
			   unsigned char *key, unsigned int key_len,
			   unsigned char **cipher, unsigned int *cipher_len)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	int ret = 0;
	int rounds = 5;

	unsigned char enc_key[AES_KEYSIZE_256] = { 0 };
	unsigned char iv[AES_BLOCK_SIZE] = { 0 };
	unsigned char salt[8] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07};

	EVP_CIPHER_CTX ctx;

	int c_len = 0;
	int f_len = 0;

	OpenSSL_add_all_digests();
	ERR_load_crypto_strings();

	//----------------------------------------------------------------//

	//~ derive encryption key
	ret = EVP_BytesToKey(EVP_aes_256_cbc(),EVP_sha256(),
						 salt,
						 key,key_len,
						 rounds,
						 enc_key,iv);
	
	if ( ret != AES_KEYSIZE_256 ) {
		fprintf(stderr,
			"ERROR: EVP_BytesToKey(): key len is %d Bytes (it shloud be 32 Bytes)\n",
			ret);
		return SKLOG_FAILURE;
	}

	//~ initialize EVP context
	EVP_CIPHER_CTX_init(&ctx);

	if ( !EVP_EncryptInit_ex(&ctx,EVP_aes_256_cbc(),NULL,enc_key,iv) ) {
		ERR_print_errors_fp(stderr);
		EVP_CIPHER_CTX_cleanup(&ctx);
		return SKLOG_FAILURE;
	}

	//~ allocate memory for the cipher-text
	c_len = plain_len+EVP_CIPHER_CTX_block_size(&ctx);
	*cipher = calloc(c_len,sizeof(char));

	if ( *cipher == NULL ) {
		fprintf(stderr,
			"ERROR: calloc(): failure");
		return SKLOG_FAILURE;
	}

	//~ encrypt plain-text
	if ( !EVP_EncryptUpdate(&ctx,*cipher,&c_len,plain,plain_len)) {
		ERR_print_errors_fp(stderr);
		EVP_CIPHER_CTX_cleanup(&ctx);
		return SKLOG_FAILURE;
	}

	if ( !EVP_EncryptFinal_ex(&ctx,*cipher+c_len,&f_len) ) {
		ERR_print_errors_fp(stderr);
		EVP_CIPHER_CTX_cleanup(&ctx);
		return SKLOG_FAILURE;
	}

	*cipher_len = c_len + f_len;

	//----------------------------------------------------------------//

	//~ some free's
	EVP_CIPHER_CTX_cleanup(&ctx);
	ERR_free_strings();

	return SKLOG_SUCCESS;
}

SKLOG_RETURN
aes256_decrypt(unsigned char *cipher, unsigned int cipher_len,
			   unsigned char *key, unsigned int key_len,
			   unsigned char **plain, unsigned int *plain_len)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	int ret = 0;
	
	int rounds = 5;
	unsigned char enc_key[AES_KEYSIZE_256] = { 0 };
	unsigned char iv[AES_BLOCK_SIZE] = { 0 };
	unsigned char salt[8] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07};

	EVP_CIPHER_CTX ctx;

	int p_len = 0;
	int f_len = 0;

	OpenSSL_add_all_digests();
	ERR_load_crypto_strings();

	//~ derive decryption key

	ret = EVP_BytesToKey(EVP_aes_256_cbc(),EVP_sha256(),
						 salt,
						 key,key_len,
						 rounds,
						 enc_key,iv);
	
	if ( ret != AES_KEYSIZE_256 ) {
		fprintf(stderr,
			"ERROR: EVP_BytesToKey(): key len is %d Bytes (it shloud be 32 Bytes)\n",
			ret);
		return SKLOG_FAILURE;
	}

	//~ initialize EVP context

	EVP_CIPHER_CTX_init(&ctx);

	if ( !EVP_DecryptInit_ex(&ctx,EVP_aes_256_cbc(),NULL,enc_key,iv) ) {
		ERR_print_errors_fp(stderr);
		EVP_CIPHER_CTX_cleanup(&ctx);
		return SKLOG_FAILURE;
	}

	//~ allocate memory for the plain-text
	
	p_len = cipher_len;
	*plain = calloc(p_len,sizeof(char));

	if ( *plain == NULL ) {
		fprintf(stderr,
			"ERROR: calloc(): failure");
		return SKLOG_FAILURE;
	}

	//~ decrypt cipher-text

	if ( !EVP_DecryptUpdate(&ctx,*plain,&p_len,cipher,cipher_len)) {
		ERR_print_errors_fp(stderr);
		EVP_CIPHER_CTX_cleanup(&ctx);
		return SKLOG_FAILURE;
	}

	if ( !EVP_DecryptFinal_ex(&ctx,*plain+p_len,&f_len) ) {
		ERR_print_errors_fp(stderr);
		EVP_CIPHER_CTX_cleanup(&ctx);
		return SKLOG_FAILURE;
	}

	*plain_len = p_len + f_len;

	//~ some free's
	
	EVP_CIPHER_CTX_cleanup(&ctx);
	ERR_free_strings();

	return SKLOG_SUCCESS;
}

SKLOG_RETURN
sha256(unsigned char *message, unsigned int message_len,
	   unsigned char *hash, unsigned int *hash_len)
{
	#ifdef DO_TRACE
	DEBUG;
	#endif

	int retval = 0;
	
	unsigned char md[SHA256_LEN] = { 0 };
	unsigned int md_len = 0;

	EVP_MD_CTX mdctx;

	OpenSSL_add_all_digests();
	ERR_load_crypto_strings();
	
	EVP_MD_CTX_init(&mdctx);
	retval = EVP_DigestInit_ex(&mdctx,EVP_sha256(),NULL);

	if ( retval == 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}
	
	retval = EVP_DigestUpdate(&mdctx,message,message_len);
	if ( retval == 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}
	
	retval = EVP_DigestFinal_ex(&mdctx,md,&md_len);
	if ( retval == 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}
	
	EVP_MD_CTX_cleanup(&mdctx);
	memcpy(hash,md,md_len);
	if ( hash_len > 0 )
		*hash_len = md_len;

	ERR_free_strings();
	EVP_cleanup();
	return SKLOG_SUCCESS;
	
error:
	ERR_free_strings();
	EVP_cleanup();
	return SKLOG_FAILURE;
}


SKLOG_RETURN
hmac(unsigned char *message, unsigned int message_len, 
	 unsigned char *key, unsigned int key_len, unsigned char *hmac,
	 unsigned int *hmac_len)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	unsigned char buf[SKLOG_BUFFER_LEN] = { 0 };
	unsigned int bufl = 0;

	HMAC_CTX mdctx;

	OpenSSL_add_all_digests();
	ERR_load_crypto_strings();

	//----------------------------------------------------------------//

	HMAC_CTX_init(&mdctx);

	if ( !message ) {
		ERROR("hmac() error: 1st argument must be not null");
		goto error;
	}

	if ( !key ) {
		ERROR("hmac() error: 3rd argument must be not null");
		goto error;
	}

	if ( !hmac ) {
		ERROR("hmac() error: 5th argument must be not null");
		goto error;
	}

	if ( HMAC_Init_ex(&mdctx,key,key_len,EVP_sha256(),NULL) == 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	if ( HMAC_Update(&mdctx,message,message_len) == 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	if ( HMAC_Final(&mdctx,buf,&bufl) == 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	HMAC_CTX_cleanup(&mdctx);

	memcpy(hmac,buf,bufl);

	if ( hmac_len != 0) 
		*hmac_len = bufl;

	//----------------------------------------------------------------//

	ERR_free_strings();
	return SKLOG_SUCCESS;

error:
	HMAC_CTX_cleanup(&mdctx);
	ERR_free_strings();
	return SKLOG_FAILURE;
}

SKLOG_RETURN
b64_enc(unsigned char *blob, unsigned int blob_len, char **b64_blob)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	BIO *bmem = 0;
	BIO *b64 = 0;
	BUF_MEM *bptr = 0;

	char *out = 0;

	SSL_load_error_strings();

	if ( (b64 = BIO_new(BIO_f_base64())) == NULL ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	
	if ( (bmem = BIO_new(BIO_s_mem())) == NULL ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}
	
	b64 = BIO_push(b64, bmem);

	if ( BIO_write(b64,blob,blob_len) < 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	if ( BIO_flush(b64) <= 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}
	
	BIO_get_mem_ptr(b64, &bptr);

	if ( ( out = calloc(bptr->length+1,sizeof(char)) ) == NULL ) {
		ERROR("calloc() failure");
		goto error;
	}
	
	memcpy(out,bptr->data,bptr->length);
	out[bptr->length] = 0;

	BIO_free_all(b64);

	*b64_blob = out;

	ERR_free_strings();
	return SKLOG_SUCCESS;

error:
	ERR_free_strings();
	return SKLOG_FAILURE;
}

SKLOG_RETURN
b64_dec(char *b64_blob, unsigned int b64_blob_len,
		unsigned char **blob, unsigned int *blob_len)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	BIO *b64 = 0;
	BIO *bmem = 0;

	unsigned char *buf = 0;
	unsigned int bufl = 0;

	SSL_load_error_strings();

	if ( ( buf = calloc(b64_blob_len,sizeof(char)) ) == NULL ) {
		ERROR("calloc() failure");
		goto error;
	}
	memset(buf,0,b64_blob_len);

	if ( (b64 = BIO_new(BIO_f_base64())) == NULL ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	if ( (bmem = BIO_new_mem_buf(b64_blob,b64_blob_len)) == NULL ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	bmem = BIO_push(b64,bmem);

	if ( (bufl = BIO_read(bmem,buf,b64_blob_len)) < 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	BIO_free_all(bmem);

	*blob = buf;
	*blob_len = bufl;

	ERR_free_strings();
	return SKLOG_SUCCESS;
	
error:
	ERR_free_strings();
	return SKLOG_FAILURE;
}

/*--------------------------------------------------------------------*/
/*						 tlv management							 */
/*--------------------------------------------------------------------*/

SKLOG_RETURN
tlv_parse(unsigned char *tlv_msg, uint32_t type, void *data,
		  unsigned int *data_len)
{
	#ifdef DO_DEEP_TRACE
	DEBUG
	#endif

	if ( tlv_msg == NULL ) {
		ERROR("unsigned char *tlv_msg must be NOT NULL")
		return SKLOG_FAILURE;
	}

	#ifdef DO_TRACE_X
	int y = 0;
	for ( y = 0 ; y < 4 ; y++ )
		fprintf(stderr,"%2.2x ",tlv_msg[y]);
	fprintf(stderr,"\n");
	for ( ; y < 8 ; y++ )
		fprintf(stderr,"%2.2x ",tlv_msg[y]);
	fprintf(stderr,"\n");
	#endif

	unsigned int len = 0;

	uint32_t tmp = 0;

	memcpy(&tmp,tlv_msg,4);
	tmp = ntohl(tmp);

	if ( tmp != type ) {
		WARNING("Message not well formed!!!")
		return SKLOG_FAILURE;
	}

	memcpy(&len,&tlv_msg[4],4);
	len = ntohl(len);

	memcpy(data,&tlv_msg[8],len);
	*data_len = len;

	return SKLOG_SUCCESS;
}

SKLOG_RETURN
tlv_get_type(unsigned char *tlv_msg, uint32_t *type)
{
	uint32_t tmp = 0;

	if ( tlv_msg == 0 ) {
		ERROR("argument 1 must be not null");
		return SKLOG_FAILURE;
	}

	if ( type == 0 ) {
		ERROR("argument 2 must be not null");
		return SKLOG_FAILURE;
	}
		
	memcpy(&tmp,tlv_msg,4);
	*type = ntohl(tmp);
	
	return SKLOG_SUCCESS;
}

SKLOG_RETURN
tlv_get_len(unsigned char *tlv_msg, unsigned int *len)
{
	unsigned int  tmp = 0;

	if ( tlv_msg == 0 ) {
		ERROR("argument 1 must be not null");
		return SKLOG_FAILURE;
	}

	if ( len == 0 ) {
		ERROR("argument 2 must be not null");
		return SKLOG_FAILURE;
	}
		
	memcpy(&tmp,&tlv_msg[4],4);
	*len = ntohl(tmp);
	
	return SKLOG_SUCCESS;
}

SKLOG_RETURN
tlv_get_value(unsigned char	*tlv_msg, unsigned char	**value)
{
	unsigned char *tmp = 0;
	unsigned int len1 = 0;
	unsigned int len2 = 0;

	memcpy(&len1,&tlv_msg[4],sizeof(len1));
	len2 = ntohl(len1);

	tmp = calloc(len2,sizeof(char));
	memcpy(tmp,&tlv_msg[8],len2);
	*value = tmp;

	return SKLOG_SUCCESS;
}

SKLOG_RETURN
tlv_parse_message(unsigned char	*msg, uint32_t expected_type,
				  uint32_t *type, unsigned int *len,
				  unsigned char	**value)
{
	#ifdef DO_DEEP_TRACE
	DEBUG
	#endif

	uint32_t t = 0;
	unsigned int l = 0;
	unsigned char *v = 0;

	if ( msg == NULL ) {
		ERROR("msg must be not null")
		goto error;
	}

	if ( tlv_get_type(msg,&t) == SKLOG_FAILURE ) {
		ERROR("tlv_get_type() failure");
		goto error;
	}
	if ( expected_type != NOTYPE ) {
		if ( t != expected_type ) {
			ERROR("malformed message");
			goto error;
		}
	}

	if ( tlv_get_len(msg,&l) == SKLOG_FAILURE ) {
		ERROR("tlv_get_len() failure");
		goto error;
	}

	if ( tlv_get_value(msg,&v) == SKLOG_FAILURE ) {
		ERROR("tlv_get_value() failure");
		goto error;
	}

	if ( type != NULL ) *type= t;
	*len = l;
	*value = v;

	return SKLOG_SUCCESS;

error:
	return SKLOG_FAILURE;
}				  

SKLOG_RETURN
tlv_create_message(uint32_t type, unsigned int len,
				   unsigned char *value, unsigned char **message,
				   unsigned int *message_len)
{
	#ifdef DO_DEEP_TRACE
	DEBUG
	#endif

	uint32_t t = 0;
	unsigned int l = 0;
	
	unsigned char *buffer = 0;

	if ( value == NULL && len > 0 ) {
		ERROR("if len is great then 0 value must be not null");
		goto error;
	}

	t = htonl(type);
	l = htonl(len);

	buffer = calloc(len+8,sizeof(unsigned char));

	if ( buffer == NULL ) {
		ERROR("calloc() failue");
		goto error;
	}

	memcpy(buffer,&t,sizeof(t));
	memcpy(buffer+4,&l,sizeof(l));

	if ( len > 0 && value != NULL )
		memcpy(buffer+8,value,len);

	*message = buffer;
	*message_len = len + 8;
	
	return SKLOG_SUCCESS;

error:
	if ( buffer > 0 ) free(buffer);
	return SKLOG_FAILURE;
}

/*--------------------------------------------------------------------*/
/*					  timestamp management						  */
/*--------------------------------------------------------------------*/

SKLOG_RETURN
serialize_timeval(struct timeval *time, unsigned char **buf,
				  unsigned int *buf_len)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	uint64_t sec = 0;
	uint64_t usec = 0;

	sec = htonl(time->tv_sec);
	usec = htonl(time->tv_usec);

	*buf_len = 2*sizeof(uint64_t);
	
	if ( SKLOG_alloc(buf,unsigned char,*buf_len) == SKLOG_FAILURE ) {
		ERROR("SKLOG_alloc() failure");
		return SKLOG_FAILURE;
	}
	
	memcpy(*buf,&sec,sizeof(uint64_t));
	memcpy(*buf+sizeof(uint64_t),&usec,sizeof(uint64_t));
	
	return SKLOG_SUCCESS;
}

SKLOG_RETURN
deserialize_timeval(unsigned char *buf, unsigned int buf_len,
					struct timeval *time)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	uint64_t sec = 0;
	uint64_t usec = 0;

	memcpy(&sec,buf,sizeof(uint64_t));
	memcpy(&usec,&buf[sizeof(uint64_t)],sizeof(uint64_t));

	time->tv_sec = ntohl(sec);
	time->tv_usec = ntohl(usec);

	return SKLOG_SUCCESS;
}

SKLOG_RETURN
time_now_usec(unsigned long *usec)
{
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	int rv = 0;
	
	struct timeval tv;
	struct timezone tz;
	
	/* initialize tv and tz structures */
	
	memset(&tv, 0, sizeof(tv));
	memset(&tz, 0, sizeof(tz));
	
	/* get current time */
	
	rv = gettimeofday(&tv, &tz);
	
	if ( rv < 0 ) {
		ERROR("gettimeofday() failure");
		return SKLOG_FAILURE;
	}
	
	/* return time in microseconds */
	
	*usec = (tv.tv_usec+(tv.tv_sec*10E6));
	
	return SKLOG_SUCCESS;
}

SKLOG_RETURN
time_usec2ascii(char *ascii_time, unsigned long usec_time)
{
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	int rv = 0;
	
	struct timeval tv;
	
	char buf[ASCII_TIME_STR_LEN+1] = { 0 };
	
	long int sec = 0;
	long int usec = 0;
	
	/* initialize tv and tz structures */
	
	memset(&tv, 0, sizeof(tv));

	/* fit usec_time in tv structure */
	
	sec = usec_time/10E6;
	usec = usec_time - (sec * 10E6);
	
	tv.tv_sec = sec;
	tv.tv_usec = usec;
	
	/* convert time in ASCII */
	
	rv = strftime(buf, ASCII_TIME_STR_LEN, STR_FORMAT_TIME,
		localtime(&tv.tv_sec));
	
	if ( rv < 0 ) {
		ERROR("strftime() failure");
		return SKLOG_FAILURE;
	}
	
	memcpy(ascii_time, buf, rv);
	
	return SKLOG_SUCCESS;
}

SKLOG_RETURN 
time_serialize(unsigned char **buf, unsigned int *bufl,
			   unsigned long usec_time)
{
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	unsigned char b[8] = { 0 };
	
	uint64_t val = 0;
	uint32_t val_h = 0;
	uint32_t val_l = 0;
	
	uint32_t val_h_no = 0;
	uint32_t val_l_no = 0;
	
	val = usec_time;
	val_l = val;
	val_h = val >> 32;
	
	val_h_no = htonl(val_h);
	val_l_no = htonl(val_l);
	
	memcpy(b, &val_h_no, sizeof(val_h_no));
	memcpy(b+sizeof(val_h_no), &val_l_no, sizeof(val_l_no));
	
	*bufl = sizeof(val_h_no) + sizeof(val_l_no);
	*buf = calloc(sizeof(val_h_no) + sizeof(val_l_no), sizeof(char));
	memcpy(*buf, b, sizeof(val_h_no) + sizeof(val_l_no));
	
	return SKLOG_SUCCESS;
}

SKLOG_RETURN
time_deserialize(unsigned long *usec_time, unsigned char *buf,
				 unsigned int bufl)
{
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	uint64_t val = 0;
	uint32_t val_h = 0;
	uint32_t val_l = 0;
	
	uint32_t val_h_no = 0;
	uint32_t val_l_no = 0;
	
	memcpy(&val_h_no, buf, sizeof(val_h_no));
	memcpy(&val_l_no, buf+sizeof(val_h_no), sizeof(val_l_no));
	
	val_h = ntohl(val_h_no);
	val_l = ntohl(val_l_no);
	
	val = val_h;
	val = val << 32;
	val = val | val_l;
	
	*usec_time = val;
	
	return SKLOG_SUCCESS;
}
	
/*--------------------------------------------------------------------*/
/*					   memory management							*/
/*--------------------------------------------------------------------*/

SKLOG_RETURN
mem_alloc_n(void **mem, size_t size, size_t	count)
{
	#ifdef DO_DEEP_TRACE
	DEBUG
	#endif

	*mem = calloc(count,size);
	if (*mem == NULL)
		return SKLOG_FAILURE;
	return SKLOG_SUCCESS;
}

SKLOG_RETURN
mem_free(void **mem)
{
	#ifdef DO_DEEP_TRACE
	DEBUG
	#endif

	free(*mem);
	*mem = NULL;

	return SKLOG_SUCCESS;
}

/*--------------------------------------------------------------------*/
/*					 logfile flush management					   */
/*--------------------------------------------------------------------*/

SKLOG_RETURN
#ifdef USE_SSL
flush_logfile_send_logentry(SSL *ssl, char*f_uuid, unsigned char *type,
							unsigned int type_len,
							unsigned char *data_enc,
							unsigned int data_enc_len, unsigned char *y,
							unsigned int y_len, unsigned char *z,
							unsigned int z_len)
#endif
#ifdef USE_BIO
flush_logfile_send_logentry(BIO *bio, char*f_uuid, unsigned char *type,
							unsigned int type_len,
							unsigned char *data_enc,
							unsigned int data_enc_len, unsigned char *y,
							unsigned int y_len, unsigned char *z,
							unsigned int z_len)
#endif
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	unsigned char buffer[SKLOG_BUFFER_LEN] = { 0 };
	unsigned int ds = 0;

	unsigned char value[SKLOG_BUFFER_LEN] = { 0 };
	unsigned int len = 0;
	unsigned char *tlv = 0;

	unsigned char wbuf[SKLOG_BUFFER_LEN] = { 0 };
	unsigned int wlen = 0;
	
	unsigned char rbuf[SKLOG_BUFFER_LEN] = { 0 };
	unsigned int rlen = 0;

	SKLOG_TLV_TYPE t = 0;
	
	SSL_load_error_strings();

	memcpy(value,f_uuid,strlen(f_uuid));
	if ( tlv_create_message(ID_LOG,strlen(f_uuid),value,&tlv,&len) == SKLOG_FAILURE ) {
		ERROR("tlv_create() failure")
		goto error;
	}
	memcpy(buffer+ds,tlv,len); free(tlv); ds += len;
	
	if ( tlv_create_message(LOGENTRY_TYPE,type_len,type,&tlv,&len) == SKLOG_FAILURE ) {
		ERROR("tlv_create() failure")
		goto error;
	}
	memcpy(buffer+ds,tlv,len); free(tlv); ds += len;

	if ( tlv_create_message(LOGENTRY_DATA,data_enc_len,data_enc,&tlv,&len) == SKLOG_FAILURE ) {
		ERROR("tlv_create() failure")
		goto error;
	}
	memcpy(buffer+ds,tlv,len); free(tlv); ds += len;
	
	if ( tlv_create_message(LOGENTRY_HASH,y_len,y,&tlv,&len) == SKLOG_FAILURE ) {
		ERROR("tlv_create() failure")
		goto error;
	}
	memcpy(buffer+ds,tlv,len); free(tlv); ds += len;
	
	if ( tlv_create_message(LOGENTRY_HMAC,z_len,z,&tlv,&len) == SKLOG_FAILURE ) {
		ERROR("tlv_create() failure")
		goto error;
	}
	memcpy(buffer+ds,tlv,len); free(tlv); ds += len;

	if ( tlv_create_message(UPLOAD_LOGENTRY,ds,buffer,&tlv,&len) == SKLOG_FAILURE ) {
		ERROR("tlv_create() failure")
		goto error;
	}

	memcpy(wbuf,tlv,len);
	wlen = len;
	
	write2file("notest/u_out_upload.dat", "a+", wbuf, wlen);
	
	#ifdef USE_BIO
	if ( BIO_write(bio,wbuf,wlen) <= 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	if ( (rlen = BIO_read(bio,rbuf,SKLOG_BUFFER_LEN)) <= 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}
	#endif

	#ifdef USE_SSL
	if ( SSL_write(ssl,wbuf,wlen) <= 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	if ( (rlen = SSL_read(ssl,rbuf,SKLOG_BUFFER_LEN)) <= 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}
	#endif
	
	write2file("notest/u_in_upload.dat", "a+", rbuf, rlen);
	
	if ( tlv_get_type(rbuf,&t) == SKLOG_FAILURE ) {
		ERROR("tlv_get_type() error");
		goto error;
	}

	switch ( t ) {
		case UPLOAD_LOGENTRY_ACK:
			break;
		case UPLOAD_LOGENTRY_NACK:
			break;
		default:
			ERROR("protocol error");
			goto error;
	}   

	ERR_free_strings();
	return SKLOG_SUCCESS;
	
error:
	ERR_free_strings();
	return SKLOG_FAILURE;
}

/*--------------------------------------------------------------------*/
/*						 conenctions								*/
/*--------------------------------------------------------------------*/

/**
SKLOG_CONNECTION*
new_connection(void)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	SKLOG_CONNECTION *c = 0;

	c = calloc(1,sizeof(SKLOG_CONNECTION));

	if ( c == 0 ) {
		ERROR("calloc() failure");
		return NULL;
	}

	memset(c,0,sizeof(c));

	return c;
}
*/

/**
SKLOG_RETURN
free_conenction(SKLOG_CONNECTION *c)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	if ( c > 0 ) free(c);

	return SKLOG_SUCCESS;
}
*/

/**
SKLOG_RETURN
setup_ssl_connection(SKLOG_CONNECTION	*c,
					 const char		  *s_addr,
					 short int		   s_port,
				 //~ const char		  *cert_file_path,
					 X509				*cert,
				 //~ const char		  *key_file_path,
					 EVP_PKEY			*privkey,
					 const char		  *cacert_file_path,
					 int				 enable_verify)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	SSL_CTX *ctx = 0;
	SSL *ssl = 0;
	int ret = 0;

	int sock = 0;
	struct sockaddr_in server_addr;

	BIO *sock_bio = 0;
	//~ BIO *ssl_bio = 0;
	//~ BIO *bio = 0;
	
	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();

	//-------------initialize SSL_CTX and SSL structures--------------//

	//~ create SSL_CTX structure
	ctx = SSL_CTX_new(SSLv3_method());

	//~ load server certificate
	//~ ret = SSL_CTX_use_certificate_file(ctx,cert_file_path,SSL_FILETYPE_PEM);
	ret = SSL_CTX_use_certificate(ctx,cert);

	if ( ret <= 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	//~ load server private key
	//~ ret = SSL_CTX_use_PrivateKey_file(ctx,key_file_path,SSL_FILETYPE_PEM);
	ret = SSL_CTX_use_PrivateKey(ctx,privkey);

	if ( ret <= 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	//~ check private key
	if ( SSL_CTX_check_private_key(ctx) <= 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	if ( enable_verify ) {

		//~ load CA certificate
		ret = SSL_CTX_load_verify_locations(ctx,cacert_file_path,NULL);
	
		if ( ret <= 0 ) {
			ERR_print_errors_fp(stderr);
			goto error;
		}

		//~ set verification parameters
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER,NULL);
		SSL_CTX_set_verify_depth(ctx, 1);
	}

	ssl = SSL_new(ctx);

	//------------------create connection socket----------------------//

	sock = socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);

	if ( sock <= 0 ) {
		ERROR("socket() failure");
		goto error;
	}

	memset(&server_addr,0,sizeof(server_addr));
	server_addr.sin_family	  = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr(s_addr);
	server_addr.sin_port		= htons(s_port);

	ret = connect(sock,(struct sockaddr*)&server_addr, sizeof(server_addr));

	if ( ret < 0 ) {
		ERROR("connect() failure");
		goto error;
	}

	//---------------------setup bio structure------------------------//

	sock_bio = BIO_new(BIO_s_socket());
	BIO_set_fd(sock_bio, sock, BIO_NOCLOSE);
	SSL_set_bio(ssl, sock_bio, sock_bio);

	if ( SSL_connect(ssl) < 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	c->ssl_ctx = ctx;
	c->ssl = ssl;
	c->csock = sock;
	c->bio = sock_bio;
	
	//~ if ( ( bio = BIO_new(BIO_f_buffer()) ) == NULL ) {
		//~ ERR_print_errors_fp(stderr);
		goto child_error;
	//~ } 
	//~ 
	//~ if ( (ssl_bio = BIO_new(BIO_f_ssl())) == NULL ) {
		//~ ERR_print_errors_fp(stderr);
		goto child_error;
	//~ }
	//~ 
	//~ BIO_set_ssl(ssl_bio, ssl, BIO_CLOSE);
	//~ BIO_push(bio, ssl_bio);
	//~ 
	//~ c->bio = bio;
	//~ c->ssl_bio = ssl_bio;

	ERR_free_strings();
	return SKLOG_SUCCESS;

error:

	if ( sock_bio > 0 ) BIO_free_all(sock_bio);
	if ( ssl > 0 ) SSL_free(ssl);
	if ( ctx > 0 ) SSL_CTX_free(ctx);
	
	ERR_free_strings();
	return SKLOG_FAILURE;
}
*/

/**
SKLOG_RETURN
destroy_ssl_connection(SKLOG_CONNECTION *c)
{
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	int rv = SKLOG_SUCCESS;
	
	if ( c == NULL ) {
		ERROR("argument 1 must be not NULL");
		return SKLOG_FAILURE;
	}
	
	SSL_load_error_strings();

	//~ BIO_free_all(c->bio);
	
	if ( SSL_shutdown(c->ssl) < 0 ) {
		ERR_print_errors_fp(stderr);
		rv = SKLOG_FAILURE;
		goto error;
	}
	
	SSL_free(c->ssl);
	SSL_CTX_free(c->ssl_ctx);

	if ( close(c->csock) < 0 ) {
		ERROR(strerror(errno));
		rv = SKLOG_FAILURE;
	}

error:
	ERR_free_strings();
	return rv;
}
*/

/** do not delete
SSL_CTX*
init_ssl_ctx(const char	*cert_file_path,
			 const char	*key_file_path,
			 const char	*ca_file_path,
			 int		   enable_verify)
{
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	SSL_CTX *ctx = 0;
	int ret = 0;
	
	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();

	//~ create SSL_CTX structure
	ctx = SSL_CTX_new(SSLv3_method());

	//~ load server certificate
	ret = SSL_CTX_use_certificate_file(ctx,cert_file_path,SSL_FILETYPE_PEM);

	if ( ret <= 0 ) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	//~ load server private key
	ret = SSL_CTX_use_PrivateKey_file(ctx,key_file_path,SSL_FILETYPE_PEM);

	if ( ret <= 0 ) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	if ( enable_verify ) {

		//~ load CA certificate
		ret = SSL_CTX_load_verify_locations(ctx,ca_file_path,NULL);
	
		if ( ret <= 0 ) {
			ERR_print_errors_fp(stderr);
			return NULL;
		}

		//~ set verification parameters
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER,NULL);
		SSL_CTX_set_verify_depth(ctx, 1);
	}

	return ctx;
}
*/

/** to delete
SSL*
init_ssl_structure_s(SSL_CTX	*ctx,
				   int		socket,
				   int		verify)
{
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	SSL *ssl = 0;

	char *str = 0;
	X509 *client_cert = NULL;

	SSL_load_error_strings();

	if ( (ssl = SSL_new(ctx)) == NULL ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}
	

	SSL_set_fd(ssl, socket);
	
	if ( SSL_accept(ssl) < 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}
	
	if ( verify == 1 ) {

		client_cert = SSL_get_peer_certificate(ssl);

		if ( client_cert != NULL ) {

			fprintf(stdout,"Client certificate:\n");

			str = X509_NAME_oneline(X509_get_subject_name(client_cert),
									0,0);
			
			if ( str == NULL ) {
				ERROR("X509_NAME_oneline() failure")
				goto error;
			}
			
			fprintf(stdout,"\t subject: %s\n",str);
			free (str);

			str = X509_NAME_oneline(X509_get_issuer_name(client_cert),
									0,0);

			if ( str == NULL ) {
				ERR_print_errors_fp(stderr);
				goto error;
			}

			fprintf(stdout,"\t issuer: %s\n", str);
			SKLOG_free(&str);
			
			X509_free(client_cert);
		} else {
			NOTIFY("The SSL client does not have certificate");
		}
	}

	ERR_free_strings();
	return ssl;

error:
	ERR_free_strings();
	return NULL;
}
*/

/** to delete
SSL*
init_ssl_structure_c(SSL_CTX *ctx,int socket)
{
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	SSL *ssl = 0;

	if ( (ssl = SSL_new(ctx)) == NULL ) {
		ERROR("SSL_new() failure")
		goto error;
	}
	
	SSL_set_fd(ssl,socket);
	
	if ( SSL_connect(ssl) < 0 ) {
		ERROR("SSL_connect() failure")
		goto error;
	}

	#ifdef DO_NOTIFY

	char *str = 0;
	X509 *server_cert = 0;

	server_cert = SSL_get_peer_certificate (ssl);	
	
	if ( server_cert != NULL ) {

		fprintf(stderr,"Server certificate:\n");
		
		str = X509_NAME_oneline(X509_get_subject_name(server_cert),0,0);
		if ( str != NULL ) { 
			fprintf (stderr,"\t subject: %s\n", str);
			free (str);
		}

		str = X509_NAME_oneline(X509_get_issuer_name(server_cert),0,0);
		if ( str != NULL ) {
			fprintf (stderr,"\t issuer: %s\n", str);
			free(str);
		}
		
		X509_free (server_cert);
	} else {
		fprintf(stderr,"The SSL server does not have certificate.\n");
	}

	#endif

	return ssl;
	
error:
	if ( ssl ) SSL_free(ssl);
	return NULL;
}
*/

/**
int
tcp_bind(const char	*address,
		 short int	 port)
{
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	int skt = 0;
	int optval = 1;
	struct sockaddr_in sa_serv;
	
	if ( (skt = socket(PF_INET,SOCK_STREAM,IPPROTO_TCP)) < 0 ) {
		ERROR("socket() failure")
		return -1;
	}

	setsockopt(skt,SOL_SOCKET,SO_REUSEADDR,&optval,sizeof(optval));

	memset(&sa_serv,0,sizeof(sa_serv));
	sa_serv.sin_family = AF_INET;
	sa_serv.sin_addr.s_addr = inet_addr(address);
	sa_serv.sin_port = htons(port);

	if ( bind(skt,(struct sockaddr*)&sa_serv,sizeof(sa_serv)) < 0 ) {
		ERROR("bind() failure")
		return -1;
	}

	NOTIFY("bind to %s:%d", inet_ntoa(sa_serv.sin_addr),
		ntohs(sa_serv.sin_port));

	return skt;
}
*/

/**
int
tcp_connect(const char *address, short int port)
{
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	int skt = 0;
	struct sockaddr_in server_addr;

	skt = socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);

	if ( skt < 0 ) {
		ERROR("socket() failure")
		return -1;
	}
	
	memset (&server_addr,0,sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	server_addr.sin_addr.s_addr = inet_addr(address);
	
	//~ Establish a TCP/IP connection to the SSL client
	
	NOTIFY(address)
	
	if ( connect(skt, (struct sockaddr*) &server_addr,
				 sizeof(server_addr)) < 0 ) {
		ERROR("connect() failure")
		return -1;
	}
	
	return skt;
}
*/

/** to delete
int
sock_connect(const char *s_addr,
			 short int s_port)
{
	int csock = 0;
	struct sockaddr_in server_addr;
	int ret = 0;
	
	//~ create listener socket
	csock = socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);

	if ( csock <= 0 ) {
		fprintf(stderr,"socket() failure: %s\n",strerror(errno));
		return -1;
	}

	memset(&server_addr,0,sizeof(server_addr));
	server_addr.sin_family	  = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr(s_addr);
	server_addr.sin_port		= htons(s_port);

	ret = connect(csock,(struct sockaddr*)&server_addr, sizeof(server_addr));

	if ( ret < 0 ) {
		fprintf(stderr,"connect() failure: %s\n",strerror(errno));
		return -1;
	}
	
	return csock;
}
*/

/** to delete
SKLOG_RETURN //~ to delete
conn_close(SKLOG_CONNECTION	*conn)
{
	
	SSL_shutdown(conn->ssl);

	BIO_free_all(conn->sbio);
	SSL_free(conn->ssl);
	SSL_CTX_free(conn->ssl_ctx);
	close(conn->socket);
	

	return SKLOG_SUCCESS;
}
*/

/*--------------------------------------------------------------------*/
/*					  user messages management					  */
/*--------------------------------------------------------------------*/

void
sklog_show_buffer(int pid, const char *file, int line, const char *func,
				  const char *bufname, unsigned char *buf,
				  unsigned int bufl)
{
	char *b64 = 0;
	//~ FILE *fp = 0;
	b64_enc(buf,bufl,&b64) ;
	
	//~ fp = fopen("buffer.dat","a+");
	fprintf(stderr,
		"[BUFFER] (%d) Libsklog (%s:%d) %s(): { %s | %d | %s }\n",
		pid, file, line, func, bufname, bufl, b64);
	free(b64);
	//~ fclose(fp);
	return;
}				  

/*--------------------------------------------------------------------*/
/*							  uuid								  */
/*--------------------------------------------------------------------*/

int
sklog_uuid_unparse(uuid_t u, char *out)
{
	/*
	 * The logfile_id is an UUID which is used to identify a
	 * logging session. Such as id is placed as SYSLOGTAG into
	 * the logentries. In the RFC 3164, the dimension on SYSLOGTAG is
	 * limited to 32 character but the function uuid_unparse_lower()
	 * convert logfile_id in a 36 character string, hence it can't be
	 * used.
	 * 
	 * The function sklog_uuid_unparse() produce the same result of
	 * the function uuid_unparse_lower() removing the four characters
	 * '-' which are part of the standard UUID structure.
	 * 
	 * Esamples:
	 * 
	 * uuid_unparse_lower() produces:
	 * 		
	 * 		b188dc8a-6877-11e1-a215-0025b345ca14 (36 characters)
	 * 
	 * sklog_uuid_unparse() produces:
	 * 
	 * 		b188dc8a687711e1a2150025b345ca14 (32 characters)
	 * 
	 * Ref: http://www.ietf.org/rfc/rfc3164.txt - Section 4.1.3
	 */
	  
	int i = 0;
	int j = 0;
	
	for( i = 0 , j = 0 ; i < UUID_LEN ; i++ , j+=2 )
		sprintf(&out[j],"%2.2x",u[i]);
		
	return 0;
}

void
write2file(const char *file, const char *mode, unsigned char *buf,
		   unsigned int bufl)
{
	FILE *fp = 0;
	char *b64 = 0;
	
	if ( (fp = fopen(file, mode)) != NULL ) {
		b64_enc(buf, bufl, &b64);
		fprintf(fp, "%s\n", b64);
		free(b64);
		fclose(fp);
	}

	return;
}


/*--------------------------------------------------------------------*/
/*							networking							  */
/*--------------------------------------------------------------------*/

SKLOG_RETURN
tcp_accept(int lsock, int *csock, char *cli_addr)
{
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	int sock = 0;
	
	int rv = 0;
	
	struct sockaddr_in addr;
	socklen_t addr_len;
	
	memset(&addr, 0, sizeof(addr));
	addr_len = sizeof(addr);
	
	sock = accept(lsock, (struct sockaddr *) &addr, &addr_len);
	
	if ( sock < 0 ) {
		ERROR("accept() failure");
		return SKLOG_FAILURE;
	}
	
	memset(&addr, 0, sizeof(addr));
	addr_len = sizeof(addr);
	rv = getpeername(sock, (struct sockaddr *) &addr, &addr_len);
	
	if ( rv < 0 ) {
		close(sock);
		ERROR("getpeername() failure");
		return SKLOG_FAILURE;
	}
	
	NOTIFY("accepted connection from host: %s, port: %d",
		inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
		
	*csock = sock;
	snprintf(cli_addr, INET_ADDRSTRLEN, "%s", inet_ntoa(addr.sin_addr));
	
	return SKLOG_SUCCESS;
}

SKLOG_RETURN
tcp_bind(int lsock, const char *addr, short int port)
{
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	int rv = 0;
	
	struct sockaddr_in sa_addr;
	
	memset(&sa_addr, 0, sizeof(sa_addr));
	
	sa_addr.sin_family = AF_INET;
	sa_addr.sin_addr.s_addr = inet_addr(addr);
	sa_addr.sin_port = htons(port);
	
	rv = bind(lsock, (struct sockaddr*) &sa_addr, sizeof(sa_addr));
	
	if ( rv < 0 ) {
		ERROR("bind() failure");
		return SKLOG_FAILURE;
	}
	
	NOTIFY("bind to %s:%d", inet_ntoa(sa_addr.sin_addr),
		ntohs(sa_addr.sin_port));

	return SKLOG_SUCCESS;
}

SKLOG_RETURN
tcp_connect(int csock, const char *addr, short int port)
{
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	int rv = 0;
	
	struct sockaddr_in sa_addr;
	
	memset(&sa_addr, 0, sizeof(sa_addr));
	
	sa_addr.sin_family = AF_INET;
	sa_addr.sin_addr.s_addr = inet_addr(addr);
	sa_addr.sin_port = htons(port);
	
	rv = connect(csock, (struct sockaddr*) &sa_addr, sizeof(sa_addr));
	
	if ( rv < 0 ) {
		ERROR("bind() failure");
		return SKLOG_FAILURE;
	}
	
	NOTIFY("connect to %s:%d", inet_ntoa(sa_addr.sin_addr),
		ntohs(sa_addr.sin_port));

	return SKLOG_SUCCESS;
}

SKLOG_RETURN
tcp_listen(int lsock)
{
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	int rv = 0;
	
	rv = listen(lsock, SOMAXCONN);
	
	if ( rv < 0 ) {
		ERROR("listen() failure");
		return SKLOG_FAILURE;
	}
	
	return SKLOG_SUCCESS;
}

SKLOG_RETURN
tcp_read(void)
{
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	return SKLOG_SUCCESS;
}

SKLOG_RETURN
tcp_socket(int *sock)
{
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	int rv = 0;
	
	int tsock = 0;
	int opt_value = 1;
	
	tsock = socket(AF_INET, SOCK_STREAM, 0);
	
	if ( tsock < 0 ) {
		ERROR("socket() failure");
		return SKLOG_FAILURE;
	}
	
	rv = setsockopt(tsock, SOL_SOCKET, SO_REUSEADDR, 
		&opt_value, sizeof(opt_value));
	
	if ( rv < 0 ) {
		ERROR("setsockopt() failure");
		return SKLOG_FAILURE;
	}
	
	*sock = tsock;
	
	return SKLOG_SUCCESS;
}

SKLOG_RETURN
tcp_write(void)
{
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	return SKLOG_SUCCESS;
}

SKLOG_RETURN
ssl_init_SSL(SSL_CTX *ssl_ctx, SSL **ssl)
{
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	SSL *tssl = 0;
	
	/* check input parameters */
	
	if ( ssl_ctx == NULL ) {
		ERROR("Bad input parameter(s). Please double-check it!");
		goto error;
	}
	
	/* initialize OpenSSL */
	
	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();
	
	/* init SSL struct */ 
	
	tssl = SSL_new(ssl_ctx);
	
	if ( !tssl ) {
		ERROR("SSL_new() failure");
		ERR_print_errors_fp(stderr);
		goto error;
	}
	
	*ssl = tssl;
	
	ERR_free_strings();
	
	return SKLOG_SUCCESS;
	
error:

	if ( tssl > 0)
		SSL_free(tssl);
		
	ERR_free_strings();
	
	return SKLOG_FAILURE;
}

SKLOG_RETURN
ssl_init_SSL_CTX(const SSL_METHOD *method, const char *cert_path,
				 const char *privkey_path, int do_verify,
				 const char *CA_cert_path, SSL_CTX **ssl_ctx)
{
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	int rv = 0;
	
	SSL_CTX *tssl_ctx = 0;
	
	X509 *cert = 0;
	EVP_PKEY *privkey = 0;
	
	FILE *fp = 0;
	
	/* check input parameters */
	
	if ( cert_path == 0 || privkey_path == 0 ) {
		ERROR("Bad input parameter(s). Please double-check it!");
		goto input_params_error;
	}
	
	/* initialize OpenSSL library */
	
	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();
	
	/* init SSL_CTX  struct */ 
	
	tssl_ctx = SSL_CTX_new(method);
	
	if ( !tssl_ctx ) {
		ERROR("SSL_CTX_new() failure");
		ERR_print_errors_fp(stderr);
		goto error;
	}
		
	/* load server cert */
	
	fp = fopen(cert_path, "r");
	
	if ( fp == NULL ) {
		ERROR("Unable to open file %s", cert_path);
		goto error;
	}
	
	if ( PEM_read_X509(fp, &cert, 0, 0) == NULL ) {
		ERROR("PEM_read_X509() failure");
		ERR_print_errors_fp(stderr);
		goto error;
	}
	
	rv = SSL_CTX_use_certificate(tssl_ctx, cert);
	
	if ( rv <= 0 ) {
		ERROR("SSL_CTX_use_certificate() failure");
		ERR_print_errors_fp(stderr);
		goto error;
	} 
	
	fclose(fp);
	
	/* load server privkey */
	
	fp = fopen(privkey_path, "r");
	
	if ( fp == NULL ) {
		ERROR("Unable to open file %s", privkey_path);
		goto error;
	}
	
	if ( PEM_read_PrivateKey(fp, &privkey, 0, 0) == NULL ) {
		ERROR("PEM_read_PrivateKey() failure");
		ERR_print_errors_fp(stderr);
		goto error;
	}
	
	rv = SSL_CTX_use_PrivateKey(tssl_ctx, privkey);
	
	if ( rv <= 0 ) {
		ERROR("SSL_CTX_use_PrivateKey() failure");
		ERR_print_errors_fp(stderr);
		goto error;
	}
	
	fclose(fp);
	
	/* check privkey */ 
	
	rv = SSL_CTX_check_private_key(tssl_ctx);
	
	if ( rv <= 0 ) {
		ERROR("SSL_CTX_check_private_key() failure");
		ERR_print_errors_fp(stderr);
		goto error;
	}
	
	/* verify certificate */
	
	if ( do_verify ) { 
		/**
		 * to be implemented
		 */
	}
	
	*ssl_ctx = tssl_ctx;
	
	ERR_free_strings();
	
	return SKLOG_SUCCESS;
	
error:

	if ( fp > 0 )
		fclose(fp);
		
	if ( tssl_ctx )
		SSL_CTX_free(tssl_ctx);
		
	if ( cert > 0 )
		X509_free(cert);
			
	if ( privkey )
		EVP_PKEY_free(privkey);
		
	ERR_free_strings();
	
input_params_error:

	return SKLOG_FAILURE;
}
