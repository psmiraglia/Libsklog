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

#include "sklog_u_internal.h"
#include "sklog_internal.h"
#include "sklog_u.h"

#ifdef UMBERLOG
	#include "umberlog.h"
#endif

#ifdef USE_FILE
    #include "storage/sklog_file.h"
#elif USE_SYSLOG
    #include "storage/sklog_syslog.h"
#elif USE_SQLITE
    #include "storage/sklog_sqlite.h"
#elif USE_MISC
    #include "storage/sklog_misc.h"
#else
    #include "storage/sklog_dummy.h"
#endif

#include <libconfig.h>
#include <string.h>
#include <unistd.h>
#include <jansson.h>

#include <netinet/in.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

#include <openssl/evp.h>
#include <openssl/ssl.h>

/*
 * generate random session key k0
 * 
 */
 
SKLOG_RETURN
gen_enc_key(SKLOG_U_Ctx *ctx, SKLOG_DATA_TYPE type,
			unsigned char *enc_key)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	unsigned char buf[SKLOG_BUFFER_LEN] = { 0 };
	unsigned int blen = 0;

	unsigned char ek[EVP_MAX_MD_SIZE] = { 0 };
	unsigned int  ek_len = 0;
	uint32_t w = 0;

	EVP_MD_CTX mdctx;

	//----------------------------------------------------------------//

	w = type;
	blen = sizeof(w);
	memcpy(buf,&w,blen); 
	
	EVP_MD_CTX_init(&mdctx);
	
	if ( EVP_DigestInit_ex(&mdctx, EVP_sha256(),NULL) == 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	if ( EVP_DigestUpdate(&mdctx,buf,blen) == 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}
	
	if ( EVP_DigestUpdate(&mdctx,ctx->auth_key,SKLOG_AUTH_KEY_LEN) == 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	if ( EVP_DigestFinal_ex(&mdctx,ek,&ek_len) == 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	EVP_MD_CTX_cleanup(&mdctx);

	if ( enc_key > 0 ) 
		memcpy(enc_key,ek,ek_len);

	//----------------------------------------------------------------//

	OpenSSL_add_all_digests();
	ERR_load_crypto_strings();

	ERR_free_strings();
	return SKLOG_SUCCESS;

error:

	EVP_MD_CTX_cleanup(&mdctx);
	
	OpenSSL_add_all_digests();
	ERR_load_crypto_strings();

	ERR_free_strings();
	return SKLOG_SUCCESS;
}

/*
 * generate hash for the logentry (Yj)
 * 
 */
 
SKLOG_RETURN
gen_hash_chain(SKLOG_U_Ctx *ctx, unsigned char *data_enc,
			   unsigned int data_enc_size, SKLOG_DATA_TYPE type,
			   unsigned char *y)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	unsigned char md[EVP_MAX_MD_SIZE] = { 0 };
	unsigned int md_len = 0;

	unsigned char buf[SKLOG_BUFFER_LEN] = { 0 };
	unsigned int bufl = 0; 

	uint32_t w = 0;

	EVP_MD_CTX mdctx;

	OpenSSL_add_all_digests();
	ERR_load_crypto_strings();
	
	//----------------------------------------------------------------//

	if ( y == 0 ) {
		ERROR("5th parameter must be not null");
		goto error;
	} 

	w = type; bufl = sizeof(w); memcpy(buf,&w,bufl);

	EVP_MD_CTX_init(&mdctx);
	
	if ( EVP_DigestInit_ex(&mdctx,EVP_sha256(),NULL) == 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	if ( EVP_DigestUpdate(&mdctx,ctx->last_hash_chain,SKLOG_HASH_CHAIN_LEN) == 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}
	
	if ( EVP_DigestUpdate(&mdctx,data_enc,data_enc_size) == 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}
	
	if ( EVP_DigestUpdate(&mdctx,buf,bufl) == 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	if ( EVP_DigestFinal_ex(&mdctx,md,&md_len) == 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	EVP_MD_CTX_cleanup(&mdctx);

	memcpy(y,md,md_len);
	memcpy(ctx->last_hash_chain,md,md_len);

	//----------------------------------------------------------------//
	
	ERR_free_strings();
	return SKLOG_SUCCESS;

error:
	EVP_MD_CTX_cleanup(&mdctx);
	ERR_free_strings();
	return SKLOG_FAILURE;

}


/*
 * generate hmac message for the logentry (Zj)
 * 
 */
 
SKLOG_RETURN
gen_hmac(SKLOG_U_Ctx *ctx, unsigned char *hash_chain,
		 unsigned char *hmac)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	int retval = 0;
	
	unsigned int hmac_len = 0;

	OpenSSL_add_all_digests();
	ERR_load_crypto_strings();

	//~ calculate HMAC using SHA256 message digest
	HMAC_CTX mdctx;
	HMAC_CTX_init(&mdctx);

	retval = HMAC_Init_ex(&mdctx,
		ctx->auth_key,
		SKLOG_AUTH_KEY_LEN,
		EVP_sha256(),
		NULL);

	if ( retval == 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}
				 
	retval = HMAC_Update(&mdctx,hash_chain,SKLOG_HASH_CHAIN_LEN);

	if ( retval == 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	retval = HMAC_Final(&mdctx,hmac,&hmac_len);

	if ( retval == 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	HMAC_CTX_cleanup(&mdctx);
	ERR_free_strings();
	return SKLOG_SUCCESS;

error:
	ERR_free_strings();
	return SKLOG_FAILURE;
}

/*
 * renew authentication key (Aj)
 * 
 */
 
SKLOG_RETURN
renew_auth_key(SKLOG_U_Ctx *ctx)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	unsigned char buf[SKLOG_BUFFER_LEN] = { 0 };
	unsigned int bufl = 0;
	
	unsigned char md[EVP_MAX_MD_SIZE] = { 0 };
	unsigned int md_len = 0;

	EVP_MD_CTX mdctx;

	OpenSSL_add_all_digests();
	ERR_load_crypto_strings();

	//----------------------------------------------------------------//

	bufl = SKLOG_AUTH_KEY_LEN; memcpy(buf,ctx->auth_key,bufl);
	memset(ctx->auth_key,0,SKLOG_AUTH_KEY_LEN);

	EVP_MD_CTX_init(&mdctx);

	if ( EVP_DigestInit_ex(&mdctx, EVP_sha256(),NULL) == 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	if ( EVP_DigestUpdate(&mdctx,buf,bufl) == 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	if ( EVP_DigestFinal_ex(&mdctx,md,&md_len) == 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	if ( md_len != SKLOG_AUTH_KEY_LEN ) {
		ERROR("Something goes wrong!!!");
		goto error;
	}

	EVP_MD_CTX_cleanup(&mdctx);

	memcpy(ctx->auth_key,md,md_len);

	//----------------------------------------------------------------//

	ERR_free_strings();
	return SKLOG_SUCCESS;

error:
	EVP_MD_CTX_cleanup(&mdctx);
	ERR_free_strings();
	return SKLOG_FAILURE;
}

/*
 * compose logentry
 * 
 */

SKLOG_RETURN
__create_logentry(SKLOG_U_Ctx *ctx,	SKLOG_DATA_TYPE type,
				  unsigned char *data, unsigned int data_len,
				  int req_blob, char **blob, unsigned int *blob_len)
{
	unsigned char enc_key[SKLOG_ENC_KEY_LEN] = {0};

	unsigned char *data_enc = 0;
	unsigned int  data_enc_len = 0;

	unsigned char hash_chain[SKLOG_HASH_CHAIN_LEN] = {0};
	
	unsigned char hmac[SKLOG_HMAC_LEN] = {0};

	if ( ctx == NULL ) {
		ERROR("argument 1 must be not null")
		goto error;
	}
	
	if ( data == NULL )
		WARNING("Data to log is NULL. It's all ok?")

	//~ generate encryption key
	if ( gen_enc_key(ctx,type,enc_key) == SKLOG_FAILURE ) {
		ERROR("gen_enc_key() failure")
		goto error;
	}

#ifdef DISABLE_ENCRYPTION
	data_enc = calloc(data_len,sizeof(char));
	if ( data_enc == 0 ) {
		ERROR("calloc() failure");
		goto error;
	}
	data_enc_len = data_len;
	memcpy(data_enc,data,data_enc_len);
#else
	//~ encrypt data using the generated encryption key

	if ( aes256_encrypt(data,data_len,enc_key,SKLOG_ENC_KEY_LEN,
						&data_enc,&data_enc_len) == SKLOG_FAILURE ) {
		ERROR("encrypt_aes256() failure")
		goto error;
	}
#endif /* DISABLE_ENCRYPTION */

	/*
	 * TEMPORARY
	 * 
	 * This piece of code avoids the problem related to the dimension
	 * of the MSG element of SYSLOG messages.
	 * 
	 * All cryptography operations related to the control log entries
	 * (Initialization and Cloure) are executed on a digest of the message
	 * in order to reduce dimension. Despite, this hack disable the
	 * access control.
	 * 
	 * A better solution must be planned! 
	 */
	
	unsigned char md[SHA256_LEN] = { 0 };
	unsigned int md_len = 0;
	
	switch (type) {
		case LogfileInitializationType:
			sha256(data_enc,data_enc_len,md,&md_len);
			//~ generate hash-chain element
			if ( gen_hash_chain(ctx,md,md_len,type,hash_chain) == SKLOG_FAILURE ) {
				ERROR("gen_hash_chain() failure")
				goto error;
			}
			free(data_enc);
			data_enc = calloc(SHA256_LEN+1,sizeof(char));
			memcpy(data_enc,md,SHA256_LEN);
			data_enc_len = SHA256_LEN;
			break;
		case ResponseMessageType:
		case AbnormalCloseType:
		case NormalCloseMessage:
		case Undefined:
			if ( gen_hash_chain(ctx,data_enc,data_enc_len,type,hash_chain) == SKLOG_FAILURE ) {
				ERROR("gen_hash_chain() failure")
				goto error;
			}
			break;
	}	
	/*
	 * *****************************************************************
	 */	

	
	/*
	 * remove comments when the issues related to the size of the
	 * message is addressed
	 *
	//~ generate hash-chain element
	if ( gen_hash_chain(ctx,data_enc,data_enc_len,type,hash_chain) == SKLOG_FAILURE ) {
		ERROR("gen_hash_chain() failure")
		goto error;
	}
	*/

	//~ generate digest of hash-chain using the auth_key A
	if ( gen_hmac(ctx,hash_chain,hmac) == SKLOG_FAILURE ) {
		ERROR("gen_hmac() failure")
		goto error;
	}

	//~ re-generate auth_key
	if ( renew_auth_key(ctx) == SKLOG_FAILURE ) {
		ERROR("renew_auth_key() failure")
		goto error;
	}

	if ( req_blob ) { 
		//~ generate blob
		int i = 0;
		char b[SKLOG_BUFFER_LEN] = { 0 };
		char *b64b = 0;

		//~ i += snprintf(b+i,SKLOG_BUFFER_LEN,"[%d",type);

		switch (type) {
			case LogfileInitializationType:
				i += snprintf(b+i,SKLOG_BUFFER_LEN,"[LogfileInitializationType]");
				b64_enc(data_enc,data_enc_len,&b64b);
				i += snprintf(b+i,SKLOG_BUFFER_LEN-i,"-[%s]",b64b);
				free(b64b);
				break;
			case ResponseMessageType:
				i += snprintf(b+i,SKLOG_BUFFER_LEN,"[ResponseMessageType]");
				b64_enc(data_enc,data_enc_len,&b64b);
				i += snprintf(b+i,SKLOG_BUFFER_LEN-i,"-[%s]",b64b);
				free(b64b);
				break;
			case AbnormalCloseType:
				i += snprintf(b+i,SKLOG_BUFFER_LEN,"[AbnormalCloseType]");
				b64_enc(data_enc,data_enc_len,&b64b);
				i += snprintf(b+i,SKLOG_BUFFER_LEN-i,"-[%s]",b64b);
				free(b64b);
				break;
			case NormalCloseMessage:
				i += snprintf(b+i,SKLOG_BUFFER_LEN,"[NormalCloseMessage]");
				b64_enc(data_enc,data_enc_len,&b64b);
				i += snprintf(b+i,SKLOG_BUFFER_LEN-i,"-[%s]",b64b);
				free(b64b);
				break;
			case Undefined:
				i += snprintf(b+i,SKLOG_BUFFER_LEN,"[Undefined]");
				i += snprintf(b+i,SKLOG_BUFFER_LEN-i,"-[%s]",data_enc);
				break;
		}

		/**
		switch (type) {
			case LogfileInitializationType:
			case ResponseMessageType:
			case AbnormalCloseType:
			case NormalCloseMessage:
				b64_enc(data_enc,data_enc_len,&b64b);
				i += snprintf(b+i,SKLOG_BUFFER_LEN-i,"|%s",b64b);
				free(b64b);
				break;
			case Undefined:
				i += snprintf(b+i,SKLOG_BUFFER_LEN-i,"|%s",data_enc);
				break;
		}
		*/
		

		b64_enc(hash_chain,SKLOG_HASH_CHAIN_LEN,&b64b);
		i += snprintf(b+i,SKLOG_BUFFER_LEN-i,"-[%s]",b64b);
		free(b64b);
		b64_enc(hmac,SKLOG_HMAC_LEN,&b64b);
		i += snprintf(b+i,SKLOG_BUFFER_LEN-i,"-[%s]",b64b);
		free(b64b);

		*blob = calloc(strlen(b),sizeof(char));
		memcpy(*blob,b,strlen(b));
		*blob_len = strlen(b);
	}
	

	//~ store log entry
	if ( ctx->lsdriver->store_logentry
			(ctx->logfile_id,type,data_enc,data_enc_len,hash_chain,hmac)
				== SKLOG_FAILURE ) {
		ERROR("store_logentry() failure")
		goto error;
	}

	/*
	if ( store_logentry(type,data_enc,data_enc_len,
						hash_chain,hmac) == SKLOG_FAILURE ) {
		ERROR("store_logentry() failure")
		goto error;
	}
	*/

	//~ increase logentry counter
	ctx->logfile_counter += 1;

	return SKLOG_SUCCESS;

error:
	if ( data_enc > 0 ) free(data_enc);
	return SKLOG_FAILURE;
}	

SKLOG_RETURN
__create_logentry_umberlog(SKLOG_U_Ctx *ctx, SKLOG_DATA_TYPE type,
						   unsigned char *data, unsigned int data_len,
						   int req_blob, char **blob,
						   unsigned int *blob_len)
{
	/*
	{
		"sk_type": "0x00000002",
		"sk_data": "...",
		"sk_hash": "...",
		"sk_hmac": "..."
	}
	*/
		
	
	int rv = SKLOG_SUCCESS;
	
#ifndef DISABLE_ENCRYPTION	
	unsigned char enc_key[SKLOG_AUTH_KEY_LEN] = { 0x0 };
#endif
	
	unsigned char *enc_data = 0;
	unsigned int enc_data_len = 0;
	char *enc_data_b64 = 0;
	
	unsigned char hash[SKLOG_HASH_CHAIN_LEN] = { 0x0 };
	char *hash_b64 = 0;
	
	unsigned char hmac[SKLOG_HMAC_LEN] = { 0x0 };
	char *hmac_b64 = 0;
	
	char session_id[UUID_STR_LEN+1] = { 0x0 };
	
	char *ul_str = 0;
	char data_str[BUF_4096+1] = { 0x0 };
	char *data_b64 = 0;
	
	unsigned char buf[BUF_8192+1] = { 0x0 };
	unsigned int bufl = 0;
	
	char *logentry = 0x0;
	int logentry_len = 0;
	
	json_error_t json_error;
	json_t *root = 0;
	json_t *umberlog_data = 0;
	json_t *string = 0;
	json_t *integer = 0;
	char *json_str = 0;
	
	/* check input parameters */
	
	if ( ctx == NULL || data == NULL ) {
		ERROR("Bad input parameter(s). Please double-check it!");
		rv = SKLOG_FAILURE;
		goto check_input_error;
	}
	
	/* generate data */
	
	if ( type == LogfileInitializationType || type == ResponseMessageType) {
		
		rv = b64_enc(data, data_len, &data_b64);
		
		if ( rv == SKLOG_FAILURE ) {
			ERROR("b64_enc() failure");
			goto error;
		}
		
		memcpy(data_str, data_b64, strlen(data_b64));
		free(data_b64);
	} else {
		memcpy(data_str, data, data_len);
	}
	
	ul_str = ul_format(LOG_NOTICE, "%s", data_str, NULL);
		
	if ( ul_str == NULL ) {
		ERROR("ul_format() failure");
		goto error;
	}
	
	/* generate ubmerlog_data JSON object */
	
	umberlog_data = json_loads(ul_str, JSON_DECODE_ANY, &json_error);
	
	if ( umberlog_data == NULL ) {
		ERROR("json_loads() failure: %s", json_error.text);
		goto error;
	}
	
	json_str = json_dumps(umberlog_data, JSON_COMPACT | 
		JSON_PRESERVE_ORDER | JSON_ENSURE_ASCII);
	
	memcpy(buf, json_str, strlen(json_str));
	bufl = strlen(json_str);
	
	free(json_str);
	json_str = 0;
	
#ifdef DISABLE_ENCRYPTION

	enc_data_len = bufl;
	enc_data = calloc(bufl+1, sizeof(char));
	
	if ( enc_data == NULL ) {
		ERROR("calloc() failure");
		goto error;
	}
	
	memset(enc_data, 0, bufl+1);
	memcpy(enc_data, buf, bufl);
	
#else

	/* genrate encryption key */
	
	rv = gen_enc_key(ctx, type, enc_key);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("gen_enc_key() failure");
		goto error;
	}
	
	/* encrypt data */
	
	/*
	rv = aes256_encrypt(data, data_len, enc_key, SKLOG_ENC_KEY_LEN,
		&enc_data, &enc_data_len);
	*/
	
	rv = aes256_encrypt(buf, bufl, enc_key, SKLOG_ENC_KEY_LEN,
		&enc_data, &enc_data_len);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("aes256_encrypt() failure");
		goto error;
	}
	
#endif	
	
	/* calculate hash */
	
	rv = gen_hash_chain(ctx, enc_data, enc_data_len, type, hash);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("gen_hash_chain() failure");
		goto error;
	}
	
	/* calculate hmac */
	
	rv = gen_hmac(ctx, hash, hmac);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("gen_hmac() failure");
		goto error;
	}
	
	/* renew authkey */
	
	rv = renew_auth_key(ctx);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("renew_auth_key() failure");
		goto error;
	}
	
	/* compose logentry */
	
	uuid_unparse_lower(ctx->logfile_id, session_id);

#ifdef DISABLE_ENCRYPTION
	
	enc_data_b64 = calloc(enc_data_len+1, sizeof(char));
	
	if ( enc_data_b64 == NULL ) {
		ERROR("calloc() failure");
		goto error;
	}
	
	memset(enc_data_b64, 0, enc_data_len+1);
	memcpy(enc_data_b64, enc_data, enc_data_len);

#else

	rv = b64_enc(enc_data, enc_data_len, &enc_data_b64);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("b64_enc() failure");
		goto error;
	}
	
#endif
	
	rv = b64_enc(hash, SKLOG_HASH_CHAIN_LEN, &hash_b64);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("b64_enc() failure");
		goto error;
	}
	
	rv = b64_enc(hmac, SKLOG_HMAC_LEN, &hmac_b64);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("b64_enc() failure");
		goto error;
	}
	
	/* compose */
	
	root = json_object();
	
	if ( root == NULL ) {
		ERROR("json_object() failure");
		goto error;
	}
	
	/* append sk_session */
	
	string = json_string(session_id);
	
	if ( string == NULL ) {
		ERROR("json_string() failure");
		goto error;
	}
	
	rv = json_object_set_new(root, "sk_session", string);
	
	if ( rv < 0 ) {
		ERROR("json_object_set_new() failure");
		goto error;
	}
	
	/* append sk_type */
	
	integer = json_integer(type);
	
	if ( integer == NULL ) {
		ERROR("json_integer() failure");
		goto error;
	}
	
	rv = json_object_set_new(root, "sk_type", integer);
	
	if ( rv < 0 ) {
		ERROR("json_object_set_new() failure");
		goto error;
	}

#ifdef DISABLE_ENCRYPTION

	/* append sk_data */
	
	rv = json_object_set_new(root, "sk_data", umberlog_data);
	
	if ( rv < 0 ) {
		ERROR("json_object_set_new() failure");
		goto error;
	}
	
#else

	/* append sk_data */
	
	string = json_string(enc_data_b64);
	
	if ( string == NULL ) {
		ERROR("json_string() failure");
		goto error;
	}
	
	rv = json_object_set_new(root, "sk_data", string);
	
	if ( rv < 0 ) {
		ERROR("json_object_set_new() failure");
		goto error;
	}
	
#endif

	/* append sk_hash */
	
	string = json_string(hash_b64);
	
	if ( string == NULL ) {
		ERROR("json_string() failure");
		goto error;
	}
	
	rv = json_object_set_new(root, "sk_hash", string);
	
	if ( rv < 0 ) {
		ERROR("json_object_set_new() failure");
		goto error;
	}
	
	/* append sk_hmac */
	
	string = json_string(hmac_b64);
	
	if ( string == NULL ) {
		ERROR("json_string() failure");
		goto error;
	}
	
	rv = json_object_set_new(root, "sk_hmac", string);
	
	if ( rv < 0 ) {
		ERROR("json_object_set_new() failure");
		goto error;
	}
	
	/* save data */
	
	logentry = json_dumps(root, JSON_COMPACT | JSON_PRESERVE_ORDER | 
		JSON_ENSURE_ASCII);
	
	if ( logentry == NULL ) {
		ERROR("json_dumps() failure");
		goto error;
	}
	
	logentry_len = strlen(logentry);
	
	*blob = calloc(logentry_len+1, sizeof(char));
	
	if ( *blob == NULL ) {
		ERROR("calloc() failure");
		goto error;
	}
	
	memset(*blob, 0, logentry_len+1);
	memcpy(*blob, logentry, logentry_len);
	
	/* free memory */

	free(logentry);
	logentry = 0;
	
	free(enc_data_b64);
	enc_data_b64 = 0;
	
	free(hash_b64);
	hash_b64 = 0;
	
	free(hmac_b64);
	hmac_b64 = 0;
	
	/* store logentry */
	
#ifdef USE_MISC

	rv = ctx->lsdriver->store_logentry_v2(session_id, *blob);
		
	if ( rv == SKLOG_FAILURE ) {
		ERROR("lsdriver->store_logentry() failure");
		goto error;
	}
	
#else

	rv = ctx->lsdriver->store_logentry(ctx->logfile_id, type,
		enc_data, enc_data_len, hash, hmac);
		
	if ( rv == SKLOG_FAILURE ) {
		ERROR("lsdriver->store_logentry() failure");
		goto error;
	}
	
#endif
	
	/* increase counter */
	
	ctx->logfile_counter += 1;
	
error:

	if ( enc_data_b64 )
		free(enc_data_b64);
		
	if ( hash_b64 )	
		free(hash_b64);
		
	if ( hmac_b64 )
		free(hmac_b64);
		
	if ( json_str )
		free(json_str);
		
	if ( logentry )
		free(logentry);
		
	if ( enc_data )
		free(enc_data);

check_input_error:

	return rv;
}

SKLOG_RETURN
create_logentry(SKLOG_U_Ctx *ctx, SKLOG_DATA_TYPE type,
				unsigned char *data, unsigned int data_len,
				int req_blob, char **blob, unsigned int *blob_len)
{
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	int rv = 0;
	
	#ifdef UMBERLOG
		rv = __create_logentry_umberlog(ctx, type, data, data_len,
			req_blob, blob, blob_len);
	#else
		rv = __create_logentry(ctx, type, data, data_len, req_blob,
			blob, blob_len);
	#endif
	
	#ifdef DO_TRACE
	SHOW_JSON(*blob);
	#endif
	
	return rv;
}
	
/*
 * parse U configuration file
 * 
 */

SKLOG_RETURN
parse_u_config_file(char *t_cert_path, char *t_address, int *t_port,
					char *u_cert_path, char *u_id, char *u_privkey_path,
					unsigned int *u_timeout,
					unsigned int *logfile_max_size)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	config_t cfg;
	
	const char *str_value = 0;
	int int_value = 0;
	
	/* initialize cfg structure */
	
	config_init(&cfg);
	
	/* read configuration file */
	
	if ( !config_read_file(&cfg, SKLOG_U_CONFIG_FILE_PATH) ) {
		ERROR("%s:%d - %s", config_error_file(&cfg),
			config_error_line(&cfg), config_error_text(&cfg));
		config_destroy(&cfg);
		return SKLOG_FAILURE;
	}
	
	/* looking for t_cert */
	
	if ( config_lookup_string(&cfg, "t_cert", &str_value) ) {
		memcpy(t_cert_path, str_value, strlen(str_value));
	} else {
		memcpy(t_cert_path, SKLOG_DEF_T_CERT_PATH,
			strlen(SKLOG_DEF_T_CERT_PATH));
	}
	
	/* looking for t_address */
	
	if ( config_lookup_string(&cfg, "t_address", &str_value) ) {
		memcpy(t_address, str_value, strlen(str_value));
	} else {
		memcpy(t_address, SKLOG_DEF_T_ADDRESS,
			strlen(SKLOG_DEF_T_ADDRESS));
	}
	
	/* looking for t_port */
	
	if ( config_lookup_int(&cfg, "t_port", &int_value) ) {
		*t_port = int_value;
	} else {
		*t_port = SKLOG_DEF_T_PORT;
	}
	
	/* looking for u_cert */
	
	if ( config_lookup_string(&cfg, "u_cert", &str_value) ) {
		memcpy(u_cert_path, str_value, strlen(str_value));
	} else {
		memcpy(u_cert_path, SKLOG_DEF_U_CERT_PATH,
			strlen(SKLOG_DEF_U_CERT_PATH));
	}
	
	/* looking for u_id */
	
	if ( config_lookup_string(&cfg, "u_id", &str_value) ) {
		memcpy(u_id, str_value, strlen(str_value));
	} else {
		memcpy(u_id, SKLOG_DEF_U_ID, strlen(SKLOG_DEF_U_ID));
	}
	
	/* looking for u_privkey */
	
	if ( config_lookup_string(&cfg, "u_privkey", &str_value) ) {
		memcpy(u_privkey_path, str_value, strlen(str_value));
	} else {
		memcpy(u_privkey_path, SKLOG_DEF_U_RSA_KEY_PATH,
			strlen(SKLOG_DEF_U_RSA_KEY_PATH));
	}
	
	/* looking for u_timeout */
	
	if ( config_lookup_int(&cfg, "u_timeout", &int_value) ) {
		*u_timeout = int_value;
	} else {
		*u_timeout = SKLOG_DEF_U_TIMEOUT;
	}
	
	/* looking for logfile_max_size */
	
	if ( config_lookup_int(&cfg, "logfile_max_size", &int_value) ) {
		*logfile_max_size = int_value;
	} else {
		*logfile_max_size = SKLOG_DEF_LOGFILE_SIZE;
	}
	
	config_destroy(&cfg);
	return SKLOG_SUCCESS;
}

/*
 * generate x0 blob
 * 
 */

SKLOG_RETURN
gen_x0(SKLOG_U_Ctx *ctx, SKLOG_PROTOCOL_STEP p,	unsigned long d,
	   unsigned char **x0, unsigned int *x0_len)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	ERR_load_crypto_strings();

	unsigned char buffer[SKLOG_BUFFER_LEN] = { 0 };
	unsigned int ds = 0;
	
	unsigned char *dbuf = 0;
	unsigned int dbuf_len = 0;
	
	unsigned char *cert = 0;
	unsigned char *cert_tmp = 0;
	unsigned int  cert_size = 0;

	unsigned char value[SKLOG_BUFFER_LEN] = { 0 };
	unsigned int len = 0;
	unsigned char *tlv = 0;

	//~ serialize timestamp (d)
	time_serialize(&dbuf, &dbuf_len, d);
	
	SHOWBUF("buffer", dbuf, dbuf_len);

	//~ serialize U's x509 certificate
	cert_size = i2d_X509(ctx->u_cert,NULL);

	if ( cert_size < 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	cert = OPENSSL_malloc(cert_size);
	cert_tmp = cert;

	/*
	 * NOTE:i2d_X509() encodes the certificate ctx->u_cert in DER
	 * format and store it in the buffer *cert_tmp. After the encode
	 * process cert_tmp pointer IS INCREMENTED!!! Damned OpenSSL!
	 */

	if ( i2d_X509(ctx->u_cert,&cert_tmp) < 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	//~ convert p in network order
	uint32_t p_net = htonl(p);

	/**
	//~ compose x0 in tlv form

	*x0_len = (sizeof(p_net) + 8) +
			  (dbuf_len + 8) +
			  (cert_size + 8) +
			  (SKLOG_AUTH_KEY_LEN + 8);

	//~ SKLOG_CALLOC(*x0,*x0_len,char)
	if ( SKLOG_alloc(x0,unsigned char, *x0_len) == SKLOG_FAILURE ) {
		ERROR("SKLOG_alloc() failure");
		goto error;
	}
	*/

	//~ TLV-ize protocol step

	memcpy(value,&p_net,sizeof(p_net));
	tlv_create_message(PROTOCOL_STEP,sizeof(p_net),value,&tlv,&len);
	memcpy(buffer+ds,tlv,len); free(tlv); ds += len;
	memset(value,0,SKLOG_BUFFER_LEN);

	//~ TLV-ize d

	tlv_create_message(TIMESTAMP,dbuf_len,dbuf,&tlv,&len);
	memcpy(buffer+ds,tlv,len); free(tlv); ds += len;
	SKLOG_free(&dbuf);

	//~ TLV-ize DER encoded C's certificate

	tlv_create_message(CERT_U,cert_size,cert,&tlv,&len);
	memcpy(buffer+ds,tlv,len); free(tlv); ds += len;

	//~ TLV-ize auth_key
	tlv_create_message(A0_KEY,SKLOG_AUTH_KEY_LEN,ctx->auth_key,&tlv,&len);
	memcpy(buffer+ds,tlv,len); free(tlv); ds += len;

	OPENSSL_free(cert);
	cert = 0;

	*x0_len = ds;
	*x0 = calloc(ds,sizeof(unsigned char));
	memcpy(*x0,buffer,ds);


	ERR_free_strings();
	return SKLOG_SUCCESS;

error:
	if ( dbuf > 0 ) free(dbuf);
	if ( cert > 0 ) OPENSSL_free(cert);
	if ( *x0 ) free(*x0);
	ERR_free_strings();
	return SKLOG_FAILURE;
}

/*
 * encrypt (x0|x0_sign) blob using k0 key
 * 
 */
 
SKLOG_RETURN
gen_e_k0(SKLOG_U_Ctx *ctx, unsigned char *x0, unsigned int x0_len,
		 unsigned char *x0_sign, unsigned int x0_sign_len,
		 unsigned char **e_k0, unsigned int *e_k0_len)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	//~
	//~ encrypt {x0|x0_signature} using session key
	//~

	unsigned char buffer[SKLOG_BUFFER_LEN] = { 0 };
	unsigned int ds = 0;

	unsigned int len = 0;
	unsigned char *tlv = 0;

	/**
	unsigned char *buffer2 = 0;
	unsigned int buffer2_len = x0_len + 8 +
							   x0_sign_len + 8;
	

	//~ SKLOG_CALLOC(buffer2,buffer2_len,char)

	if ( SKLOG_alloc(&buffer2,unsigned char,buffer2_len) == SKLOG_FAILURE ) {
		ERROR("SKLOG_alloc() failure");
		goto error;
	}

	ds = 0;
	memset(buffer,0,SKLOG_BUFFER_LEN);
	*/

	//~ TLV-ize x0

	if ( tlv_create_message(X0_BUF,x0_len,x0,&tlv,&len) == SKLOG_FAILURE )
		goto error;
	memcpy(buffer+ds,tlv,len); free(tlv); ds += len;
	
	//~ TLV-ize x0_signature
	if ( tlv_create_message(X0_SIGN_U,x0_sign_len,x0_sign,&tlv,&len) == SKLOG_FAILURE )
		goto error;
	memcpy(buffer+ds,tlv,len); free(tlv); ds += len;
	

	if ( aes256_encrypt(buffer,ds,ctx->session_key,
			SKLOG_SESSION_KEY_LEN,e_k0,e_k0_len) == SKLOG_FAILURE ) {
		ERROR("encrypt_aes256() failure");
		goto error;
	}

	return SKLOG_SUCCESS;

error:
	return SKLOG_FAILURE;
}
	
/*
 * generate m0 message
 * 
 */

SKLOG_RETURN
gen_m0(SKLOG_U_Ctx *ctx, SKLOG_PROTOCOL_STEP p, unsigned char *pke_t_k0,
	   unsigned int pke_t_k0_len, unsigned char *e_k0,
	   unsigned int e_k0_len, unsigned char **m0, unsigned int *m0_len)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	unsigned char buffer[SKLOG_BUFFER_LEN] = { 0 };
	unsigned int ds = 0;

	unsigned char *tlv = 0;
	unsigned char value[SKLOG_BUFFER_LEN] = { 0 };
	unsigned int len = 0;
	

	//~ convert p in network order
	uint32_t p_net = htonl(p);

	//~ compose M0 in tlv format
	*m0_len = (sizeof(p_net) + 8) +
			  (UUID_LEN + 8) +
			  (pke_t_k0_len + 8) +
			  (e_k0_len + 8) + 1;
	/**
	//~ SKLOG_CALLOC(*m0,*m0_len,char)

	if ( SKLOG_alloc(m0,unsigned char,*m0_len) == SKLOG_FAILURE ) {
		ERROR("SKLOG_alloc() failure");
		goto error;
	}
	*/

	//~ TLV-ize p

	memcpy(value,&p_net,sizeof(p_net));
	if ( tlv_create_message(PROTOCOL_STEP,sizeof(p_net),value,&tlv,&len) == SKLOG_FAILURE )
		goto error;
	memcpy(buffer+ds,tlv,len); ds += len; free(tlv);
	memset(value,0,SKLOG_BUFFER_LEN);

	//~ TLV-ize logfile_id

	memcpy(value,ctx->logfile_id,UUID_LEN);
	if ( tlv_create_message(ID_LOG,UUID_LEN,value,&tlv,&len) == SKLOG_FAILURE )
		goto error;
	memcpy(buffer+ds,tlv,len); ds += len; free(tlv);
	memset(value,0,SKLOG_BUFFER_LEN);

	//~ TLV-ize pke_t_k0
	
	if ( tlv_create_message(PKE_PUB_T,pke_t_k0_len,pke_t_k0,&tlv,&len) == SKLOG_FAILURE )
		goto error;
	memcpy(buffer+ds,tlv,len); ds += len; free(tlv);

	//~ TLV-ize e_k0
	if ( tlv_create_message(ENC_K0,e_k0_len,e_k0,&tlv,&len) == SKLOG_FAILURE )
		goto error;
	memcpy(buffer+ds,tlv,len); ds += len; free(tlv);

	*m0_len = ds;
	*m0 = calloc(ds,sizeof(unsigned char));
	memcpy(*m0,buffer,ds);

	return SKLOG_SUCCESS;

error:
	if ( *m0 ) free(*m0);
	return SKLOG_FAILURE;
}
	
/*
 * generate d0 data blob
 * 
 */

SKLOG_RETURN
gen_d0(SKLOG_U_Ctx *ctx, unsigned long d, unsigned long d_timeout,
	   unsigned char *m0, unsigned int m0_len, unsigned char **d0,
	   unsigned int *d0_len)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	unsigned char buffer[SKLOG_BUFFER_LEN] = { 0 };
	unsigned int ds = 0;
	
	unsigned char value[SKLOG_BUFFER_LEN] = { 0 };
	unsigned int len = 0;
	unsigned char *tlv = 0;
	
	unsigned char *dbuf = 0;
	unsigned int dbuf_len = 0;
	unsigned char *dbuf2 = 0;
	unsigned int dbuf2_len = 0;

	if ( m0 == NULL ) {
		ERROR("m0 must be NOT NULL")
		goto error;
	}

	//~ serialize timestamp (d)

	if ( time_serialize(&dbuf, &dbuf_len, d) == SKLOG_FAILURE ) {
		ERROR("time_serialize() failure");
		goto error;
	}

	//~ serialize timestamp (d_timeout)

	if ( time_serialize(&dbuf2, &dbuf2_len, d_timeout) == SKLOG_FAILURE ) {
		ERROR("time_serialize() failure");
		goto error;
	}

	//~ TLV-ize d

	if ( tlv_create_message(TIMESTAMP,dbuf_len,dbuf,&tlv,&len) == SKLOG_FAILURE) {
		ERROR("tlv_create() failure")
		goto error;
	}
	memcpy(buffer+ds,tlv,len); free(tlv); ds += len;
	SKLOG_free(&dbuf);

	//~ TLV-ize d_timeout

	if ( tlv_create_message(TIMESTAMP,dbuf2_len,dbuf2,&tlv,&len) == SKLOG_FAILURE) {
		ERROR("tlv_create() failure")
		goto error;
	}
	memcpy(buffer+ds,tlv,len); free(tlv); ds += len;
	SKLOG_free(&dbuf2);

	//~ TLV-ize log_id

	memcpy(value,&ctx->logfile_id,SKLOG_LOG_ID_LEN);
	if ( tlv_create_message(ID_LOG,SKLOG_LOG_ID_LEN,value,&tlv,&len) == SKLOG_FAILURE) {
		ERROR("tlv_create() failure")
		goto error;
	}
	memcpy(buffer+ds,tlv,len); free(tlv); ds += len;
	memset(value,0,SKLOG_BUFFER_LEN);

	//~ TLV-ize m0
	
	if ( tlv_create_message(M0_MSG,m0_len,m0,&tlv,&len) == SKLOG_FAILURE) {
		ERROR("tlv_create() failure")
		goto error;
	}
	memcpy(buffer+ds,tlv,len); free(tlv); ds += len;

	*d0 = calloc(ds,sizeof(unsigned char));
	memcpy(*d0,buffer,ds);
	*d0_len = ds;

	return SKLOG_SUCCESS;

error:
	if ( dbuf ) free(dbuf); 
	if ( dbuf2 ) free(dbuf2); 
	if ( *d0 ) free(*d0);
	return SKLOG_FAILURE;
}
	
/*
 * send m0 message to T
 * 
 */

SKLOG_RETURN
send_m0(SKLOG_CONNECTION *c, unsigned char *m0, unsigned int m0_len)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	SSL_load_error_strings();

	unsigned char *tlv = 0;
	unsigned int tlv_len = 0;
	unsigned char wbuf[SKLOG_BUFFER_LEN] = { 0 };
	unsigned int wlen = 0;

	if ( tlv_create_message(M0_MSG,m0_len,m0,&tlv,&tlv_len) == SKLOG_FAILURE ) {
		ERROR("tlv_create() failure")
		goto error;
	}

	memcpy(wbuf,tlv,tlv_len);
	wlen = tlv_len;
	free(tlv);
	
	write2file("out_m0_msg.dat", "w+", wbuf, wlen);

	#ifdef USE_BIO
	if ( BIO_write(c->bio,wbuf,wlen) <= 0 ) {
		if ( !BIO_should_retry(c->bio) ) {
			ERROR("unable to send message");
			ERR_print_errors_fp(stderr);
			return SKLOG_FAILURE;
		}
		//~ to manage
	}
	#endif

	#ifdef USE_SSL
	wlen = SSL_write(c->ssl,wbuf,m0_len+8);

	if ( wlen < 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}
	#endif
	
	ERR_free_strings();
	return SKLOG_SUCCESS;

error:
	ERR_free_strings();
	return SKLOG_FAILURE;
}
	
/*
 * receive m1 message from T
 * 
 */

SKLOG_RETURN
receive_m1(SKLOG_CONNECTION *c, unsigned char **m1,
		   unsigned int *m1_len)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	SSL_load_error_strings();
	
	unsigned char rbuf[SKLOG_BUFFER_LEN] = { 0 };
	unsigned int rlen = 0;

	SKLOG_TLV_TYPE type = 0;
	unsigned int len = 0;
	unsigned char *value = 0;
	

	//~ waiting for message

	#ifdef USE_BIO
	rlen = BIO_read(c->bio,rbuf,SKLOG_BUFFER_LEN-1);
	if ( rlen <= 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}
	#endif

	#ifdef USE_SSL
	rlen = SSL_read(c->ssl,rbuf,SKLOG_BUFFER_LEN-1);
	if ( rlen <= 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}
	#endif
	
	write2file("in_m1_msg.dat", "w+", rbuf, rlen);
	

	tlv_get_type(rbuf,&type);
	tlv_get_len(rbuf,&len);
	tlv_get_value(rbuf,&value);

	if ( type != M1_MSG ) {
		ERROR("Message is bad structured: expected M1_MSG");
		goto error;
	}

	*m1_len = len;
	*m1 = value;
	
	ERR_free_strings();
	return SKLOG_SUCCESS;

error:
	if ( *m1 > 0 ) free(*m1);
	ERR_free_strings();
	return SKLOG_FAILURE;
}
	
/*
 * parse m1 message
 * 
 */

SKLOG_RETURN
parse_m1(unsigned char *m1, unsigned int m1_len, SKLOG_PROTOCOL_STEP *p,
		 unsigned char *t_id, unsigned char **pke_u_k1,
		 unsigned int *pke_u_k1_len, unsigned char **e_k1,
		 unsigned int *e_k1_len)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	unsigned char buffer[SKLOG_BUFFER_LEN] = { 0 };
	
	unsigned int ds = 0;
	unsigned int len = 0;

	if ( tlv_parse(&m1[ds],PROTOCOL_STEP,p,&len) == SKLOG_FAILURE ) {
		ERROR("M1 message is bad structured: expected PROTOCOLO_STEP");
		goto error;
	}

	ds += len+8;
	len = 0;

	if ( tlv_parse(&m1[ds],ID_T,t_id,&len) == SKLOG_FAILURE ) {
		ERROR("M1 message is bad structured: expected ID_T");
		goto error;
	}

	ds += len+8;
	len = 0;

	if ( tlv_parse(&m1[ds],PKE_PUB_U,buffer,&len) == SKLOG_FAILURE ) {
		ERROR("M1 message is bad structured: expected PKE_PUB_U");
		goto error;
	}

	//~ SKLOG_CALLOC(*pke_u_k1,len,char)
	if ( SKLOG_alloc(pke_u_k1,unsigned char,len) == SKLOG_FAILURE ) {
		ERROR("SKLOG_alloc() failure");
		goto error;
	}
	memcpy(*pke_u_k1,buffer,len);
	*pke_u_k1_len = len;

	ds += len+8;
	len = 0;
	memset(buffer,0,SKLOG_BUFFER_LEN);

	if ( tlv_parse(&m1[ds],ENC_K1,buffer,&len) == SKLOG_FAILURE ) {
		ERROR("M1 message is bad structured: expected ENC_K1");
		goto error;
	}

	//~ SKLOG_CALLOC(*e_k1,len,char)
	if ( SKLOG_alloc(e_k1,unsigned char,len) == SKLOG_FAILURE ) {
		ERROR("SKLOG_alloc() failure");
		goto error;
	}
	memcpy(*e_k1,buffer,len);
	*e_k1_len = len;

	ds += len+8;
	len = 0;
	memset(buffer,0,SKLOG_BUFFER_LEN);

	return SKLOG_SUCCESS;

error:
	if (*pke_u_k1 > 0 ) free(*pke_u_k1);
	if (*e_k1 > 0 ) free(*e_k1);
	return SKLOG_FAILURE;
}

/*
 * parse (x1|x1_sign) blob
 * 
 */

SKLOG_RETURN
parse_e_k1_content(unsigned char *in, unsigned int in_len, 
				   unsigned char **x1, unsigned int *x1_len,
				   unsigned char **x1_sign, unsigned int *x1_sign_len)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	unsigned char buffer[SKLOG_BUFFER_LEN] = { 0 };
	unsigned int ds = 0;
	unsigned int len = 0;

	if ( tlv_parse(&in[ds],X1_BUF,buffer,&len) == SKLOG_FAILURE ) {
		ERROR("PLAIN buffer is bad structured: expected X1_BUF");
		goto error;
	}

	//~ SKLOG_CALLOC(*x1,len,char)
	if ( SKLOG_alloc(x1,unsigned char,len) == SKLOG_FAILURE ) {
		ERROR("SKLOG_alloc() failure");
		goto error;
	}

	*x1_len = len;
	memcpy(*x1,buffer,len);

	ds += len+8;
	len = 0;
	memset(buffer,0,SKLOG_BUFFER_LEN);

	if ( tlv_parse(&in[ds],X1_SIGN_T,buffer,&len) == SKLOG_FAILURE ) {
		ERROR("PLAIN buffer is bad structured: expected X1_SIGN_T");
		goto error;
	}

	//~ SKLOG_CALLOC(*x1_sign,len,char)
	if ( SKLOG_alloc(x1_sign,unsigned char,len) == SKLOG_FAILURE ) {
		ERROR("SKLOG_alloc() failure");
		goto error;
	}

	*x1_sign_len = len;
	memcpy(*x1_sign,buffer,len);

	ds += len+8;
	len = 0;
	memset(buffer,0,SKLOG_BUFFER_LEN);
	
	return SKLOG_SUCCESS;

error:
	if ( *x1 > 0 ) free(*x1);
	if ( *x1_sign > 0  ) free(*x1_sign);
	return SKLOG_FAILURE;
}
	
/*
 * verify m1 message
 * 
 */

SKLOG_RETURN
verify_m1(SKLOG_U_Ctx *ctx, unsigned char *m1, unsigned int m1_len)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	SKLOG_PROTOCOL_STEP p = 0;
	unsigned char t_id[512] = { 0 };
	unsigned char *pke_u_k1 = 0;
	unsigned int pke_u_k1_len = 0;
	unsigned char *e_k1 = 0;
	unsigned int e_k1_len = 0;

	unsigned char *k1 = 0;
	size_t k1_len = 0;
	size_t len = pke_u_k1_len;

	unsigned char *plain = 0;
	unsigned int plain_len = 0;
	len = e_k1_len;

	unsigned char *x1 = 0;
	unsigned int x1_len = 0;
	unsigned char *x1_sign = 0;
	unsigned int x1_sign_len = 0;

	EVP_PKEY *t_pubkey = NULL;
	
	/* TODO: define how to verify the message */

	ERR_load_crypto_strings();

	//~ parse m1 message
	if ( parse_m1(m1,m1_len,&p,t_id,&pke_u_k1,&pke_u_k1_len,&e_k1,
				  &e_k1_len) == SKLOG_FAILURE ) {
		ERROR("parse_m1() failure")
		goto error;
	}

	//~ decrypt k1 using U's private key
	if ( pke_decrypt(ctx->u_privkey,pke_u_k1,pke_u_k1_len,&k1,
					 &k1_len) == SKLOG_FAILURE ) {
		ERROR("pke_decrypt() failure")
		goto error;
	}

	//~ decrypt {x1,x1_sign} using k1 key 
	//~ if ( decrypt_aes256(k1,e_k1,len,&plain,
						//~ &plain_len) == SKLOG_FAILURE ) {
	
	if ( len ) ; // to fix
	
	if ( aes256_decrypt(e_k1,e_k1_len,k1,SKLOG_SESSION_KEY_LEN,&plain,
						&plain_len) == SKLOG_FAILURE ) {
		ERROR("decrypt_aes256() failure")
		goto error;
	}

	//~ parse plain
	if ( parse_e_k1_content(plain,plain_len,&x1,&x1_len,&x1_sign,
							&x1_sign_len) == SKLOG_FAILURE ) {
		ERROR("parse_plain() failure")
		goto error;
	}

	//~ verify x1_sign
	//~ todo: enhance the verification process
	if ( (t_pubkey = X509_get_pubkey(ctx->t_cert)) == NULL ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	if ( sign_verify(t_pubkey,x1_sign,x1_sign_len,x1,
					 x1_len) == SKLOG_FAILURE ) {
		ERROR("sign_verify() failure")
		goto error;
	}

	ERR_free_strings();
	
	return SKLOG_SUCCESS;

error:
	if ( pke_u_k1 > 0 ) free(pke_u_k1);
	if ( e_k1 > 0 ) free(e_k1);
	if ( k1 > 0 ) free(k1);
	if ( plain > 0 ) free(plain);
	if ( x1 > 0 ) free(x1);
	if ( x1_sign > 0 ) free(x1_sign);
	if ( t_pubkey > 0 ) EVP_PKEY_free(t_pubkey); 

	ERR_free_strings();

	return SKLOG_FAILURE;
}
	
/*
 * verify timeout expiration for receiving m1 message
 * 
 */

SKLOG_RETURN
verify_timeout_expiration(unsigned long d_timeout)
{
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	unsigned long now = 0;
	
	if ( time_now_usec(&now) == SKLOG_FAILURE ) {
		ERROR("time_now_usec() failure");
		return SKLOG_FAILURE;
	}
	
	if ( now > d_timeout ) {
		NOTIFY("Timeout expired");
		return SKLOG_FAILURE;
	}
	
	return SKLOG_SUCCESS;
}

/*
 * initialize U context
 * 
 */

SKLOG_RETURN
initialize_context(SKLOG_U_Ctx *ctx)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	//~ char			*t_cert = 0;
	//~ char			*t_address = 0;
	//~ int			 t_port = 0;
	//~ char			*u_cert = 0;
	//~ char			*u_id = 0;
	//~ char			*u_privkey = 0;
	
	char t_cert[SKLOG_SETTING_VALUE_LEN] = { 0 };
	char t_address[SKLOG_SETTING_VALUE_LEN] = { 0 };
	int t_port = 0;
	char u_cert[SKLOG_SETTING_VALUE_LEN] = { 0 };
	char u_id[SKLOG_SETTING_VALUE_LEN] = { 0 };
	char u_privkey[SKLOG_SETTING_VALUE_LEN] = { 0 };

	unsigned int u_timeout = 0;
	unsigned int logfile_size = 0;

	FILE *fp = 0;

	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	if ( ctx == NULL ) {
		ERROR("argument 1 must be not NULL")
		goto error;
	}

	//~ parse_u_config_file(&t_cert,&t_address,&t_port,&u_cert,&u_id,
					    //~ &u_privkey,&u_timeout,&logfile_size);
	
	parse_u_config_file(t_cert, t_address, &t_port, u_cert, u_id,
		u_privkey, &u_timeout, &logfile_size);

	//~ set u_id
	memset(ctx->u_id,0,HOST_NAME_MAX+1);
	memcpy(ctx->u_id,u_id,strlen(u_id)+1);

	//~ set u_id_len
	ctx->u_id_len = strlen(u_id);

	//~ set u_timeout
	ctx->u_timeout = u_timeout;

	//~ set u_cert
	memset(ctx->u_cert_file_path,0,MAX_FILE_PATH_LEN);
	memcpy(ctx->u_cert_file_path,u_cert,strlen(u_cert)+1);

	ctx->u_cert = X509_new();

	fp = fopen(u_cert,"r");
	if ( fp != NULL ) {
		if ( !PEM_read_X509(fp,&ctx->u_cert,NULL,NULL) ) {
			ERR_print_errors_fp(stderr);
			goto error;
		}
		fclose(fp);
	} else {
		ERROR("unable to read U's X509 file")
		goto error;
	}

	//~ set u_privkey
	memset(ctx->u_privkey_file_path,0,MAX_FILE_PATH_LEN);
	memcpy(ctx->u_privkey_file_path,u_privkey,strlen(u_privkey)+1);

	ctx->u_privkey = EVP_PKEY_new();
	
	fp = fopen(u_privkey,"r");
	if ( fp != NULL ) {
		if ( !PEM_read_PrivateKey(fp,&ctx->u_privkey,NULL,RSA_DEFAULT_PASSPHRASE) ) {
			ERR_print_errors_fp(stderr);
			goto error;
		}
		fclose(fp);
	} else {
		ERROR("unable to read U's private key file")
		goto error;
	}
	
	//~ set t_cert
	ctx->t_cert = X509_new();

	if ( (fp = fopen(t_cert,"r")) != NULL ) {
		if ( !PEM_read_X509(fp,&ctx->t_cert,NULL,NULL) ) {
			ERR_print_errors_fp(stderr);
			goto error;
		}
		fclose(fp);
	} else {
		ERROR("unable to read T's X509 file")
		goto error;
	}

	//~ set t_cert_path
	memset(ctx->t_cert_file_path,0,MAX_FILE_PATH_LEN);
	memcpy(ctx->t_cert_file_path,t_cert,strlen(t_cert)+1);

	//~ set t_address
	memset(ctx->t_address,0,512);
	memcpy(ctx->t_address,t_address,strlen(t_address)+1);

	//~ set t_port
	ctx->t_port = t_port;

	//~ set logfile_size
	ctx->logfile_size = logfile_size;

	//~ set logfile_counter
	ctx->logfile_counter = 0;

	//~ set logfile_id
	uuid_generate(ctx->logfile_id);

	//~ set session_key
	RAND_bytes(ctx->session_key,SKLOG_SESSION_KEY_LEN);

	//~ set auth_key
	RAND_bytes(ctx->auth_key,SKLOG_AUTH_KEY_LEN);

	//~ init last_hash_chain
	memset(ctx->last_hash_chain,0,SKLOG_HASH_CHAIN_LEN);

	//~ init x0_hash
	memset(ctx->x0_hash,0,SKLOG_HASH_CHAIN_LEN);

	// init storage callbacks
	ctx->lsdriver = calloc(1,sizeof(SKLOG_U_STORAGE_DRIVER));

	if ( ctx->lsdriver == NULL ) {
		ERROR("calloc() failure");
		goto error;
	}

	#ifdef USE_FILE
	ctx->lsdriver->store_logentry =	&sklog_file_u_store_logentry;
	ctx->lsdriver->flush_logfile =	 &sklog_file_u_flush_logfile;
	ctx->lsdriver->init_logfile =	  &sklog_file_u_init_logfile;
	#elif USE_SYSLOG
	ctx->lsdriver->store_logentry =	&sklog_syslog_u_store_logentry;
	ctx->lsdriver->flush_logfile =	 &sklog_syslog_u_flush_logfile;
	ctx->lsdriver->init_logfile =	  &sklog_syslog_u_init_logfile;
	#elif USE_SQLITE
	ctx->lsdriver->store_logentry =	&sklog_sqlite_u_store_logentry;
	ctx->lsdriver->flush_logfile =	 &sklog_sqlite_u_flush_logfile;
	ctx->lsdriver->flush_logfile_v2 =	 &sklog_sqlite_u_flush_logfile_v2;
	ctx->lsdriver->init_logfile =	  &sklog_sqlite_u_init_logfile;
	#elif USE_MISC
	ctx->lsdriver->store_logentry_v2 = &sklog_misc_u_store_logentry_v2;
	ctx->lsdriver->flush_logfile_v2 = &sklog_misc_u_flush_logfile_v2;
	ctx->lsdriver->init_logfile_v2 = &sklog_misc_u_init_logfile_v2;
	ctx->lsdriver->close_logfile_v2 = &sklog_misc_u_close_logfile_v2;
	ctx->lsdriver->dump_raw = &sklog_misc_u_dump_raw;
	ctx->lsdriver->dump_json = &sklog_misc_u_dump_json;
	ctx->lsdriver->dump_soap = &sklog_misc_u_dump_soap;
	#else
	ctx->lsdriver->store_logentry =	&sklog_dummy_u_store_logentry;
	ctx->lsdriver->flush_logfile =	 &sklog_dummy_u_flush_logfile;
	ctx->lsdriver->init_logfile =	  &sklog_dummy_u_init_logfile;
	#endif

	//~ set context_state
	ctx->context_state = SKLOG_U_CTX_INITIALIZED;
	ctx->logging_session_mgmt = 0;

	ERR_free_strings();
	return SKLOG_SUCCESS;

error:
	if ( fp > 0 ) fclose(fp);
	if ( ctx->u_cert > 0 ) X509_free(ctx->u_cert);
	if ( ctx->t_cert > 0 ) X509_free(ctx->t_cert);
	if ( ctx->u_privkey > 0 ) EVP_PKEY_free(ctx->u_privkey);

	memset(ctx,0,sizeof(ctx));

	ERR_free_strings();
	return SKLOG_FAILURE;
}

/*
 * initialize logging session
 * 
 */

SKLOG_RETURN
initialize_logging_session(SKLOG_U_Ctx *ctx, int req_blob, char **le1,
						   unsigned int *le1_len, char **le2,
						   unsigned int *le2_len)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	int retval = 0;

	unsigned long d = 0;
	unsigned long d_timeout = 0;
	unsigned long now = 0;

	unsigned char *x0 = 0;
	unsigned int x0_len = 0;
	SKLOG_PROTOCOL_STEP p = 0;

	unsigned char *pke_t_k0 = 0;
	size_t pke_t_k0_len = 0;

	unsigned char *x0_sign = 0;
	unsigned int x0_sign_len = 0;

	unsigned char *e_k0 = 0;
	unsigned int e_k0_len = 0;

	unsigned char *m0 = 0;
	unsigned int m0_len = 0;

	unsigned char *d0 = 0;
	unsigned int d0_len = 0;

	EVP_MD_CTX mdctx;

	SKLOG_CONNECTION *conn = 0;

	unsigned char *m1 = 0;
	unsigned int m1_len = 0;
	
	unsigned char *ts = 0;
	
	unsigned int data_len = 0;

	char timestamp[BUF_512+1] = { 0x0 };
	const char *reason = 0;
	
	char data[1024] = {0};

	OpenSSL_add_all_digests();
	ERR_load_crypto_strings();

	if ( data_len ) ; //to fix

	//~ get current time

	if ( time_now_usec(&d) == SKLOG_FAILURE ) {
		ERROR("time_now_usec()");
		goto error;
	}

	//~ set timeout

	d_timeout = d;
	d_timeout += ctx->u_timeout * 10E6;

	//~ generate x0
	if ( gen_x0(ctx, p , d, &x0, &x0_len) == SKLOG_FAILURE ) {
		ERROR("gen_x0() failure")
		goto error;
	}

	//~ encrypt k0 using T's public key
	if ( pke_encrypt(ctx->t_cert,ctx->session_key,
					 SKLOG_SESSION_KEY_LEN,&pke_t_k0,
					 &pke_t_k0_len) == SKLOG_FAILURE ) {
		ERROR("pke_encrypt() failure");
		goto error;
	}

	//~ sign x0 using U's private key 
	if ( sign_message(x0,x0_len,ctx->u_privkey,
					  &x0_sign,&x0_sign_len) == SKLOG_FAILURE ) {
		ERROR("sign_message() failure")
		goto error;
	}

	//~ encrypt (XO,sign_u_x0) using k0 key
	if ( gen_e_k0(ctx,x0,x0_len,x0_sign,x0_sign_len,
				  &e_k0,&e_k0_len) == SKLOG_FAILURE ) {
		ERROR("gen_e_k0() failure")
		goto error;
	}

	//~ generate M0
	if ( gen_m0(ctx,p,pke_t_k0,pke_t_k0_len,e_k0,e_k0_len,
				&m0,&m0_len) == SKLOG_FAILURE ) {
		ERROR("gen_m0() failure")
		goto error;
	}

	//~ generate d0
	if ( gen_d0(ctx, d, d_timeout, m0, m0_len,
				&d0,&d0_len) == SKLOG_FAILURE ) {
		ERROR("gen_d0() failure")
		goto error;
	}

	//~ store x0
	EVP_MD_CTX_init(&mdctx);
	retval = EVP_DigestInit_ex(&mdctx, EVP_sha256(),NULL);

	if ( retval == 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}
	
	retval = EVP_DigestUpdate(&mdctx,x0,x0_len);

	if ( retval == 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}
	
	retval = EVP_DigestFinal_ex(&mdctx,ctx->x0_hash,NULL);

	if ( retval == 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}
	
	EVP_MD_CTX_cleanup(&mdctx);

	SKLOG_free(&x0);

	//~ initialize logfile
	if ( ctx->lsdriver->init_logfile(ctx->logfile_id, d)
													== SKLOG_FAILURE ) {
		ERROR("ctx->lsdriver->init_logfile() failure");
		goto error;
	}

	//~ create firts log entry
	if ( req_blob ) { 
		if ( create_logentry(ctx,LogfileInitializationType,
							 d0,d0_len,1,le1,le1_len) == SKLOG_FAILURE ) {
			ERROR("create_logentry() failure")
			goto error;
		}
	} else {
		if ( create_logentry(ctx,LogfileInitializationType,
							 d0,d0_len,0,0,0) == SKLOG_FAILURE ) {
			ERROR("create_logentry() failure")
			goto error;
		}
	}

	//~ open connection to T

	//~ conn = new_connection();
	conn = SKLOG_CONNECTION_New();

	if ( conn == 0 ) {
		ERROR("new_connection() failure");
		goto error;
	}

	//~ retval = setup_ssl_connection(conn,ctx->t_address,ctx->t_port,
				//~ //~ ctx->u_cert_file_path,ctx->u_privkey_file_path,
				//~ ctx->u_cert,ctx->u_privkey,
				//~ ctx->t_cert_file_path,DO_NOT_VERIFY);
				
	retval = SKLOG_CONNECTION_Init(conn, ctx->t_address, ctx->t_port,
		ctx->u_cert, ctx->u_privkey, ctx->t_cert_file_path,
		DO_NOT_VERIFY);

	if ( retval == SKLOG_FAILURE ) {
		ERROR("setup_ssl_connection() failure");
		goto error;
	}

	//~ send m0 to T
	if ( send_m0(conn,m0,m0_len) == SKLOG_FAILURE ) {
		ERROR("send_m0() failure")
		goto error;
	}
	SKLOG_free(&m0);

	//~ receive m1 from T
	if ( receive_m1(conn,&m1,&m1_len) == SKLOG_FAILURE ) {
		ERROR("receive_m1() failure")
		goto error;
	}

	//~ close connection
	//~ destroy_ssl_connection(conn);
	//~ free_conenction(conn);
	SKLOG_CONNECTION_Destroy(conn);
	SKLOG_CONNECTION_Free(&conn);

	//~ verify timeout expiration
	if ( verify_timeout_expiration(d_timeout) == SKLOG_FAILURE ) {
		NOTIFY("timeout expired")
		reason = "Timeout Expiration";
		goto failure;
	}

	//~ verify M1
	if ( verify_m1(ctx,m1,m1_len) == SKLOG_FAILURE ) {
		ERROR("verify_m1() failure")
		reason = "M1 verification failure";
		goto failure;
	}

	//~ create log entry
	if ( req_blob ) {
		if ( create_logentry(ctx,ResponseMessageType,
							 m1,m1_len,1,le2,le2_len) == SKLOG_FAILURE ) {
			ERROR("create_logentry() failure")
			goto error;
		}
	} else {
		if ( create_logentry(ctx,ResponseMessageType,
							 m1,m1_len,0,0,0) == SKLOG_FAILURE ) {
			ERROR("create_logentry() failure")
			goto error;
		}
	}
	

	ERR_free_strings();
	return SKLOG_SUCCESS;

failure:
	
	time_now_usec(&now);
	time_usec2ascii(timestamp, now);
	
	strcat(data, timestamp);
	strcat(data, " - ");
	strcat(data, reason);

	if ( req_blob ) {
		if ( create_logentry(ctx,AbnormalCloseType,
							 (unsigned char *)data,
							 strlen(data),1,le2,le2_len) == SKLOG_FAILURE ) {
			ERROR("create_logentry() failure")
			goto error;
		}
	} else {
		if ( create_logentry(ctx,AbnormalCloseType,
							 (unsigned char *)data,
							 strlen(data),0,0,0) == SKLOG_FAILURE ) {
			ERROR("create_logentry() failure")
			goto error;
		}
	}
		
	SKLOG_free(&ts);
	ERR_free_strings();
	return SKLOG_FAILURE;

error:
	if ( x0 > 0 ) free(x0);
	if ( pke_t_k0 > 0 ) free(pke_t_k0);
	if ( x0_sign > 0 ) free(x0_sign);
	if ( e_k0 > 0 ) free(e_k0);
	if ( m0 > 0 ) free(m0);
	if ( d0 > 0 ) free(d0);
	if ( m1 > 0 ) free(m1);

	ERR_free_strings();
	return SKLOG_FAILURE;
}

/*
 * initialize logging file flushing procedure
 * 
 */

SKLOG_RETURN
flush_logfile_init(SKLOG_CONNECTION *c)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	unsigned char wbuf[SKLOG_SMALL_BUFFER_LEN] = { 0 };
	unsigned int wlen = 0;

	unsigned char rbuf[SKLOG_SMALL_BUFFER_LEN] = { 0 };
	unsigned int rlen = 0;

	unsigned char *tlv = 0;

	SSL_load_error_strings();

	if ( tlv_create_message(LOGFILE_UPLOAD_REQ,0,NULL,&tlv,&wlen) == SKLOG_FAILURE ) {
		ERROR("tlv_create() failure");
		goto error;
	}
	memcpy(wbuf,tlv,wlen); free(tlv);
	
	write2file("u_out_upload.dat", "w+", wbuf, wlen);
	
	#ifdef USE_BIO
	if ( BIO_write(c->bio,wbuf,wlen) <= 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}
	 
	rlen = BIO_read(c->bio,rbuf,SKLOG_SMALL_BUFFER_LEN);

	if ( rlen <= 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}
	#endif
	
	#ifdef USE_SSL
	if ( SSL_write(c->ssl,wbuf,wlen) <= 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}
	
	 
	rlen = SSL_read(c->ssl,rbuf,SKLOG_SMALL_BUFFER_LEN);
	if ( rlen <= 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}
	#endif
	
	write2file("u_in_upload.dat", "w+", rbuf, rlen);
	
	SKLOG_TLV_TYPE type = 0;
	tlv_get_type(rbuf,&type);

	switch ( type ) {
		case LOGFILE_UPLOAD_READY:
			
			NOTIFY("received LOGFILE_UPLOAD_READY");
			break;
		default:
			ERROR("unexpected message");
			goto error;
			break;
	}

	ERR_free_strings();
	return SKLOG_SUCCESS;
	
error:
	ERR_free_strings();
	return SKLOG_FAILURE;
}

/*
 * finalize logging file flushing procedure
 * 
 */
 
SKLOG_RETURN
flush_logfile_terminate(SKLOG_CONNECTION *c)
{
	unsigned char wbuf[SKLOG_SMALL_BUFFER_LEN] = { 0 };
	unsigned int wlen = 0;

	unsigned char *tlv = 0;

	SSL_load_error_strings();

	if ( tlv_create_message(LOGFILE_UPLOAD_END,0,NULL,&tlv,&wlen) == SKLOG_FAILURE ) {
		ERROR("tlv_create() failure");
		goto error;
	}
	memcpy(wbuf,tlv,wlen); free(tlv);

	write2file("u_out_upload.dat", "a+", wbuf, wlen);
	
	#ifdef USE_BIO
	if ( BIO_write(c->bio,wbuf,wlen) <= 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}
	#endif
	
	#ifdef USE_SSL
	if ( SSL_write(c->ssl,wbuf,wlen) <= 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}
	#endif 
	
	

	ERR_free_strings();
	return SKLOG_SUCCESS;

error:
	ERR_free_strings();
	return SKLOG_FAILURE;
}

/*
 * execute logging file flushing procedure
 * 
 */
 
SKLOG_RETURN
flush_logfile_execute(SKLOG_U_Ctx *ctx, unsigned long now)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	SKLOG_CONNECTION *conn = 0;
	int retval = 0;

	//~ open connection
	//~ if ( (conn = new_connection()) == 0 ) {
		//~ ERROR("new_conenction() failure");
		//~ goto error;
	//~ }
	if ( ( conn = SKLOG_CONNECTION_New() ) == 0 ) {
		ERROR("new_conenction() failure");
		goto error;
	}

	//~ retval = setup_ssl_connection(conn,ctx->t_address,ctx->t_port,
								  //~ ctx->u_cert,ctx->u_privkey,
								  //~ ctx->t_cert_file_path,DO_NOT_VERIFY);
	retval = SKLOG_CONNECTION_Init(conn, ctx->t_address,
		ctx->t_port, ctx->u_cert, ctx->u_privkey,
		ctx->t_cert_file_path, DO_NOT_VERIFY);

	if ( retval == SKLOG_FAILURE ) {
		ERROR("setup_ssl_connection() failure");
		goto error;
	}

	//~ send message: LOGFILE_FLUSH_START
	if ( flush_logfile_init(conn) == SKLOG_FAILURE ) {
		ERROR("flush_logfile_init() failure")
		goto error;
	}

	//~ flush logfile
	if ( ctx->lsdriver->flush_logfile(ctx->logfile_id, now, conn) == SKLOG_FAILURE ) {
		ERROR("ctx->lsdriver->flush_logfile() failure");
		goto error;
	}

	//~ send message: LOGFILE_FLUSH_END
	if ( flush_logfile_terminate(conn) == SKLOG_FAILURE ) {
		ERROR("flush_logfile_terminate() failure")
		goto error;
	}

	//~ close connection
	//~ destroy_ssl_connection(conn);
	//~ free_conenction(conn);
	SKLOG_CONNECTION_Destroy(conn);
	SKLOG_CONNECTION_Free(&conn);

	return SKLOG_SUCCESS;
	
error:
	return SKLOG_FAILURE;
}

/*
 * generate m0 message and put it (encoded in base64) in *m0_b64
 * geneate the first logentry and put it *le
 * 
 */

SKLOG_RETURN
generate_m0_message(SKLOG_U_Ctx *ctx, unsigned char **msg,
					unsigned int *msg_len, char **le,
					unsigned int *le_len)
{
	#ifdef DO_TRACE
	DEBUG;
	#endif
	
	int rv = SKLOG_SUCCESS;
	
	unsigned long d = 0;
	unsigned long d_timeout = 0;
	
	SKLOG_PROTOCOL_STEP p = 0;
	
	unsigned char *x0 = 0;
	unsigned int x0_len = 0;
	
	unsigned char *x0_sign = 0;
	unsigned int x0_sign_len = 0;
	
	unsigned char x0_md[SHA256_LEN] = { 0 };
	unsigned int x0_md_len = 0;
	
	unsigned char *e_k0 = 0;
	unsigned int e_k0_len = 0;
	
	unsigned char *pke_t_k0 = 0;
	size_t pke_t_k0_len = 0;
	
	unsigned char *m0 = 0;
	unsigned int m0_len = 0;
	
	unsigned char *d0 = 0;
	unsigned int d0_len = 0;
	
#ifdef USE_MISC
	char logfile_id[UUID_STR_LEN+1] = { 0x0 };
#endif	
	
	/* checking input parameters */
	
	if ( ctx == NULL ) {
		ERROR("Argument 1 must be not null");
		goto check_input_error;
	}
	
	/* get current time and set timeout */
	
	rv = time_now_usec(&d);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("time_now_usec() failure");
		goto error;
	}
	
	d_timeout = d;
	d_timeout += (ctx->u_timeout * 10E6 );
	
	ctx->u_expiration = d_timeout;
	
	/* generate x0 blob */
	
	rv = gen_x0(ctx, p, d, &x0, &x0_len);
	if ( rv == SKLOG_FAILURE ) {
		ERROR("gen_x0() failure");
		goto error;
	}
	
	/* store x0 blob digest  */
	
	rv = sha256(x0, x0_len, x0_md, &x0_md_len);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("sha256() failure");
		goto error;
	}
	
	memcpy(ctx->x0_hash, x0_md, SHA256_LEN);
	
	/* sign x0 blob using U privkey */
	
	rv = sign_message(x0, x0_len, ctx->u_privkey, &x0_sign,
		&x0_sign_len);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("sign_message() failure");
		goto error;
	}
	
	/* encrypt [x0|x0_sign] blob using k0 key */
	
	rv = gen_e_k0(ctx, x0, x0_len, x0_sign, x0_sign_len, &e_k0,
		&e_k0_len);
		
	if ( rv == SKLOG_FAILURE ) {
		ERROR("gen_e_k0() failure");
		goto error;
	}
	
	/* encrypt k0 using T pubkey */
	
	rv = pke_encrypt(ctx->t_cert, ctx->session_key,
		SKLOG_SESSION_KEY_LEN, &pke_t_k0, &pke_t_k0_len);
		
	if ( rv == SKLOG_FAILURE ) {
		ERROR("pke_encrypt() failure");
		goto error;
	}
	
	/* compose m0 message */
	
	rv = gen_m0(ctx, p, pke_t_k0, pke_t_k0_len, e_k0, e_k0_len, &m0,
		&m0_len);
		
	if ( rv == SKLOG_FAILURE ) {
		ERROR("gen_m0() failure");
		goto error;
	}
	
	/* generate d0 blob */
	
	rv = gen_d0(ctx, d, d_timeout, m0, m0_len, &d0, &d0_len);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("gen_d0() failure");
		goto error;
	}
	
	/* initialize logfile */
	
#ifdef USE_MISC
	uuid_unparse_lower(ctx->logfile_id, logfile_id);
	
	rv = ctx->lsdriver->init_logfile_v2(logfile_id, d);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("ctx->lsdriver->init_logfile() failure");
		goto error;
	}
#else
	rv = ctx->lsdriver->init_logfile(ctx->logfile_id, d);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("ctx->lsdriver->init_logfile() failure");
		goto error;
	}
#endif
	
	/* store the first logentry */
	
	rv = create_logentry(ctx, LogfileInitializationType, d0, d0_len,
		1, le,le_len);
		
	if ( rv == SKLOG_FAILURE ) {
		ERROR("create_logentry() failure");
		goto error;
	}
	
	/* encode m0 in base64 */

	*msg = m0;
	*msg_len = m0_len;
	
	/* free memory */
	
error:	
	
	if ( x0 )
		free(x0);
		
	if ( x0_sign )
		free(x0_sign);
		
	if ( e_k0 )
		free(e_k0);
		
	if ( pke_t_k0 )
		free(pke_t_k0);
		
	if ( d0 )
		free(d0);
		
	return rv;
	
check_input_error:
	return SKLOG_FAILURE;
}

/*
 * perform some protocol verification on m1 message
 * 
 */

SKLOG_RETURN
verify_m1_message(SKLOG_U_Ctx *ctx, unsigned char *m1,
				  unsigned int m1_len, char **le, unsigned int *le_len)
{
	#ifdef DO_TARCE
	DEBUG;
	#endif
	
	int rv = SKLOG_SUCCESS;
	
	unsigned char *buf = 0;
	
	unsigned long now = 0;
	char timestamp[BUF_512+1] = { 0x0 };
	char data[BUF_2048+1] = { 0x0 };
	const char *reason = 0;
	
	/* check input parameters */
	
	if ( ctx == NULL || m1 == NULL ) {
		ERROR("Bad input parameter(s). Please, double-check!");
		goto check_input_error;
	}
	
	/* verify timeout expiration */
	
	if ( verify_timeout_expiration(ctx->u_expiration) == SKLOG_FAILURE ) {
		NOTIFY("Timeout expiration");
		reason = "Timeout Expiration";
		goto failure;
	}
	
	/* verify m1 message */
	
	rv = verify_m1(ctx, m1, m1_len);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("verify_m1() failure");
		reason = "Verification Failure";
		goto failure;
	}
	
	/* create logentry */
	
	rv = create_logentry(ctx, ResponseMessageType, m1, m1_len,
		1, le, le_len);
		
	if ( rv == SKLOG_FAILURE ) {
		ERROR("create_logentry() failure");
		goto error;
	}
	
error:

	if ( buf ) 
		free(buf);
	
	return rv;
	
failure:
	
	/* get current time */
	
	if ( time_now_usec(&now) == SKLOG_FAILURE ) {
		ERROR("time_now_usec() failure");
		goto error;
	}
	
	time_usec2ascii(timestamp, now);
	
	strcat(data, timestamp);
	strcat(data, " - ");
	strcat(data, reason);
	
	/* create logentry */
	
	rv = create_logentry(ctx, AbnormalCloseType, 
		(unsigned char *)data, strlen(data), 1, le, le_len);
		
	if ( rv == SKLOG_FAILURE ) {
		ERROR("create_logentry() failure");
		goto error;
	}
	
	goto error;
	
check_input_error:
	return SKLOG_FAILURE;
}

SKLOG_RETURN
dump_raw(SKLOG_U_Ctx *ctx, const char *filename)
{
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	int rv = SKLOG_SUCCESS;
	
	char logfile_id[BUF_512+1] = { 0x0 };
	
	/* check input parameters */
	
	if ( ctx == NULL || filename == NULL ) {
		ERROR("%s", MSG_BAD_INPUT_PARAMS);
		return SKLOG_FAILURE;
	}
	
	/* dump */
	
	uuid_unparse_lower(ctx->logfile_id, logfile_id);
	
	rv = ctx->lsdriver->dump_json(logfile_id, filename);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("lsdriver->dump_raw() failure");
		return SKLOG_FAILURE;
	}
	
	return SKLOG_SUCCESS;
}

SKLOG_RETURN
dump_json(SKLOG_U_Ctx *ctx, const char *filename)
{
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	int rv = SKLOG_SUCCESS;
	
	char logfile_id[BUF_512+1] = { 0x0 };
	
	/* check input parameters */
	
	if ( ctx == NULL || filename == NULL ) {
		ERROR("%s", MSG_BAD_INPUT_PARAMS);
		return SKLOG_FAILURE;
	}
	
	/* dump */
	
	uuid_unparse_lower(ctx->logfile_id, logfile_id);
	
	rv = ctx->lsdriver->dump_json(logfile_id, filename);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("lsdriver->dump_json() failure");
		return SKLOG_FAILURE;
	}
	
	return SKLOG_SUCCESS;
}

SKLOG_RETURN
dump_soap(SKLOG_U_Ctx *ctx, const char *filename)
{
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	int rv = SKLOG_SUCCESS;
	
	char logfile_id[BUF_512+1] = { 0x0 };
	
	/* check input parameters */
	
	if ( ctx == NULL || filename == NULL ) {
		ERROR("%s", MSG_BAD_INPUT_PARAMS);
		return SKLOG_FAILURE;
	}
	
	/* dump */
	
	uuid_unparse_lower(ctx->logfile_id, logfile_id);
	
	rv = ctx->lsdriver->dump_soap(logfile_id, filename);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("lsdriver->dump_soap() failure");
		return SKLOG_FAILURE;
	}
	
	return SKLOG_SUCCESS;
}
