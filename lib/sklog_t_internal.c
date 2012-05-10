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

#include "sklog_t_internal.h"
#include "sklog_internal.h"

//~ #include <confuse.h>
#include <libconfig.h>

#include <netinet/in.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

/*
 * parse T configuration file
 * 
 */
 
SKLOG_RETURN parse_t_config_file(char *t_cert_path, char *t_privkey_path,
	char *t_privkey_passphrase, char *t_id, char *t_address,
	int *t_port)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	SKLOG_RETURN rv = SKLOG_SUCCESS;

	config_t cfg;
	
	int int_value = 0;
	const char *str_value = 0;
	
	/* initialize cfg structure */
	
	config_init(&cfg);
	
	/* read configuration file */
	
	if ( !config_read_file(&cfg, SKLOG_T_CONFIG_FILE_PATH) ) {
		ERROR("%s:%d - %s", config_error_file(&cfg),
			config_error_line(&cfg), config_error_text(&cfg));
		rv = SKLOG_FAILURE;
		goto error;
	}
	
	/* looking for t_cert_path */
	
	if ( !config_lookup_string(&cfg, "t_cert", &str_value ) ) {
		str_value = SKLOG_DEF_T_CERT_PATH;
	}
	
	memcpy(t_cert_path, str_value, strlen(str_value));
	
	/* looking for t_privkey_path */
	
	if ( !config_lookup_string(&cfg, "t_privkey", &str_value) ) {
		str_value = SKLOG_DEF_T_RSA_KEY_PATH;
	}
	
	memcpy(t_privkey_path, str_value, strlen(str_value));
	
	/* looking for t_privkey_passphrase */
	
	if ( !config_lookup_string(&cfg, "t_privkey_passphrase", &str_value) ) {
		str_value = SKLOG_DEF_T_RSA_KEY_PASSPHRASE;
	}
	
	memcpy(t_privkey_passphrase, str_value, strlen(str_value));
	
	/* looking for t_id */
	
	if ( !config_lookup_string(&cfg, "t_id", &str_value) ) {
		str_value = SKLOG_DEF_T_ID;
	}
	
	memcpy(t_id, str_value, strlen(str_value));
	
	/* looking for t_address */
	
	if ( !config_lookup_string(&cfg, "t_address", &str_value) ) {
		str_value = SKLOG_DEF_T_ADDRESS;
	}
	
	memcpy(t_address, str_value, strlen(str_value));
	
	/* looking for t_port */
	
	if ( !config_lookup_int(&cfg, "t_port", &int_value) ) {
		int_value = SKLOG_DEF_T_PORT;
	}
	
	*t_port = int_value;

error:
	config_destroy(&cfg);
	return rv;
}

/*
 * parse logging session initialization message (m0)
 * 
 */

SKLOG_RETURN parse_m0(SKLOG_T_Ctx *t_ctx, unsigned char *m0,
	unsigned int m0_len, SKLOG_PROTOCOL_STEP *p, uuid_t *logfile_id,
	unsigned char **pke_t_k0, unsigned int *pke_t_k0_len,
	unsigned char **e_k0, unsigned int *e_k0_len)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	unsigned char buffer[SKLOG_BUFFER_LEN] = { 0 };
	
	unsigned int ds = 0;
	unsigned int len = 0;

	unsigned char uuid_tmp[SKLOG_SMALL_BUFFER_LEN] = { 0 };
	uuid_t uuid;

	if ( tlv_parse(&m0[ds],PROTOCOL_STEP,p,&len) == SKLOG_FAILURE ) {
		ERROR("M1 message is bad structured: expected PROTOCOLO_STEP");
		return SKLOG_FAILURE;
	}

	ds += len+8;
	len = 0;

	if ( tlv_parse(&m0[ds],ID_LOG,uuid_tmp,&len) == SKLOG_FAILURE ) {
		ERROR("M1 message is bad structured: expected ID_U");
		return SKLOG_FAILURE;
	}

	memcpy(&uuid,uuid_tmp,len);
	uuid_copy(*logfile_id,uuid);

	ds += len+8;
	len = 0;

	if ( tlv_parse(&m0[ds],PKE_PUB_T,buffer,&len) == SKLOG_FAILURE ) {
		ERROR("M1 message is bad structured: expected PKE_PUB_T");
		return SKLOG_FAILURE;
	}

	if ( SKLOG_alloc(pke_t_k0,unsigned char,len) == SKLOG_FAILURE ) {
		ERROR("SKLOG_alloc() failure");
		return SKLOG_FAILURE;
	}
	memcpy(*pke_t_k0,buffer,len);
	*pke_t_k0_len = len;

	ds += len+8;
	len = 0;
	memset(buffer,0,SKLOG_BUFFER_LEN);

	if ( tlv_parse(&m0[ds],ENC_K0,buffer,&len) == SKLOG_FAILURE ) {
		free(*pke_t_k0);
		ERROR("M1 message is bad structured: expected ENC_K0");
		return SKLOG_FAILURE;
	}

	if ( SKLOG_alloc(e_k0,unsigned char,len) == SKLOG_FAILURE ) {
		ERROR("SKLOG_alloc() failure");
		return SKLOG_FAILURE;
	}
	memcpy(*e_k0,buffer,len);
	*e_k0_len = len;

	ds += len+8;
	len = 0;
	memset(buffer,0,SKLOG_BUFFER_LEN);

	return SKLOG_SUCCESS;
}

/*
 * verify signature included in m0 message
 * 
 */

SKLOG_RETURN verify_m0_signature(X509 *u_cert, unsigned char *x0_sign,
	size_t x0_sign_len, unsigned char *x0, unsigned int x0_len)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	EVP_PKEY *u_pubkey = 0;

	ERR_load_crypto_strings();

	if ( u_cert == NULL ) {
		ERROR("u_cert variable must be not null");
		goto error;
	}

	if ( x0_sign == NULL ) {
		ERROR("x0_sign variable must be not null");
		goto error;
	}
	if ( x0 == NULL ) {
		ERROR("x0 variable must be not null");
		goto error;
	}

	if ( (u_pubkey = X509_get_pubkey(u_cert)) == NULL ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	if ( sign_verify(u_pubkey,x0_sign,x0_sign_len,
										x0,x0_len) == SKLOG_FAILURE ) {
		ERROR("sign_verify() failure")
		goto error;
	}

	ERR_free_strings();
	EVP_PKEY_free(u_pubkey);
	
	return SKLOG_SUCCESS;

error:
	if ( u_pubkey > 0 ) EVP_PKEY_free(u_pubkey); 
	ERR_free_strings();

	return SKLOG_FAILURE;
}

/*
 * verify certificate included in m0 message
 * 
 */
 
SKLOG_RETURN verify_m0_certificate(X509 *u_cert)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	if ( u_cert == NULL ) {
		ERROR("u_cert variable must be not null");
		return SKLOG_FAILURE;
	}

	TO_IMPLEMENT;

	return SKLOG_TO_IMPLEMENT;
}

/*
 * parse blob included in m0 message that was encrypted by U using the
 * random session key K0
 * 
 */
 
SKLOG_RETURN parse_e_k0_content(unsigned char *in, unsigned int in_len,
	unsigned char **x0, unsigned int *x0_len, unsigned char **x0_sign,
	unsigned int *x0_sign_len)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	unsigned char buffer[SKLOG_BUFFER_LEN] = { 0 };
	unsigned int ds = 0;
	unsigned int len = 0;

	if ( tlv_parse(&in[ds],X0_BUF,buffer,&len) == SKLOG_FAILURE ) {
		ERROR("PLAIN buffer is bad structured: expected X0_BUF");
		return SKLOG_FAILURE;
	}

	if ( SKLOG_alloc(x0,unsigned char,len) == SKLOG_FAILURE ) {
		ERROR("SKLOG_alloc() failure");
		return SKLOG_FAILURE;
	}

	*x0_len = len;
	memcpy(*x0,buffer,len);

	ds += len+8;
	len = 0;
	memset(buffer,0,SKLOG_BUFFER_LEN);

	if ( tlv_parse(&in[ds],X0_SIGN_U,buffer,&len) == SKLOG_FAILURE ) {
		free(*x0);
		ERROR("PLAIN buffer is bad structured: expected X0_SIGN_U");
		return SKLOG_FAILURE;
	}

	if ( SKLOG_alloc(x0_sign,unsigned char,len) == SKLOG_FAILURE ) {
		ERROR("SKLOG_alloc() failure");
		return SKLOG_FAILURE;
	}

	*x0_sign_len = len;
	memcpy(*x0_sign,buffer,len);

	ds += len+8;
	len = 0;
	memset(buffer,0,SKLOG_BUFFER_LEN);
	
	return SKLOG_SUCCESS;
}

/*
 * parse x0 blob included in m0 message
 * 
 */
 
SKLOG_RETURN parse_x0( unsigned char *x0, unsigned int x0_len,
	X509 **u_cert, unsigned char *auth_key)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	unsigned char buffer[SKLOG_BUFFER_LEN] = { 0 };
	
	unsigned int ds = 0;
	unsigned int len = 0;

	unsigned char *u_cert_buf = 0;
	const unsigned char *u_cert_buf_tmp = 0;

	ERR_load_crypto_strings();

	//~ get protocol step
	if ( tlv_parse(&x0[ds],PROTOCOL_STEP,buffer,
			&len) == SKLOG_FAILURE ) {
		ERROR("X0 buffer is bad structured: expected PROTOCOLO_STEP");
		goto error;
	}
	
	ds += len+8;
	len = 0;
	memset(buffer,0,SKLOG_BUFFER_LEN);

	//~ get timestamp
	if ( tlv_parse(&x0[ds],TIMESTAMP,buffer,&len) == SKLOG_FAILURE ) {
		ERROR("X0 buffer is bad structured: expected TIMESTAMP");
		goto error;
	}

	ds += len+8;
	len = 0;
	memset(buffer,0,SKLOG_BUFFER_LEN);

	//~ get U's certificate
	if ( tlv_parse(&x0[ds],CERT_U,buffer,&len) == SKLOG_FAILURE ) {
		ERROR("X0 buffer is bad structured: expected CERT_U");
		goto error;
	}

	u_cert_buf = OPENSSL_malloc(len);
	memcpy(u_cert_buf,buffer,len);

	u_cert_buf_tmp = u_cert_buf;

	if ( d2i_X509(u_cert,&u_cert_buf_tmp,len) == NULL ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}
	
	ds += len+8;
	len = 0;
	memset(buffer,0,SKLOG_BUFFER_LEN);

	//~ get U's a0
	if (tlv_parse(&x0[ds],A0_KEY,auth_key,&len) == SKLOG_FAILURE ) {
		ERROR("X0 buffer is bad structured: expected A0_KEY");
		goto error;
	}
	
	OPENSSL_free(u_cert_buf);

	return SKLOG_SUCCESS;
	
error:
	if ( u_cert_buf > 0 ) free( u_cert_buf );
	ERR_free_strings();
	return SKLOG_FAILURE;
}

/*
 * generate x1 blob that will be included in m1 message
 * 
 */
 
SKLOG_RETURN gen_x1(SKLOG_PROTOCOL_STEP *p, unsigned char *x0,
	unsigned int x0_len, unsigned char **x1, unsigned int *x1_len)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	unsigned char x0_md[SHA256_LEN] = { 0 };
	
	unsigned char buffer[SKLOG_BUFFER_LEN] = { 0 };
	unsigned int ds = 0;

	unsigned int len = 0;
	unsigned char value[SKLOG_BUFFER_LEN] = { 0 };
	unsigned char *tlv = 0;
	
	//~ generate a digest of x0

	EVP_MD_CTX mdctx;
	EVP_MD_CTX_init(&mdctx);
	EVP_DigestInit_ex(&mdctx, EVP_sha256(),NULL);
	EVP_DigestUpdate(&mdctx,x0,x0_len);
	EVP_DigestFinal_ex(&mdctx,x0_md,NULL)  ;
	EVP_MD_CTX_cleanup(&mdctx);

	//~ increase protocol step
	uint32_t p_net = htonl(*p+1);
	*p += 1;

	/**
	//~ compose x1

	*x1_len = (sizeof(p_net) + 8) +
			  SHA256_LEN + 8;

	if ( SKLOG_alloc(x1,unsigned char,*x1_len) == SKLOG_FAILURE ) {
		ERROR("SKLOG_alloc() failure");
		return SKLOG_FAILURE;
	}
	*/

	//~ TLV-ize protocol step

	memcpy(value,&p_net,sizeof(p_net));
	tlv_create_message(PROTOCOL_STEP,sizeof(p_net),value,&tlv,&len);
	memcpy(buffer+ds,tlv,len); free(tlv); ds += len; 
	memset(value,0,SKLOG_SMALL_BUFFER_LEN);

	//~ TLV-ize protocol step

	tlv_create_message(HASH_X0,SHA256_LEN,x0_md,&tlv,&len);
	memcpy(buffer+ds,tlv,len); free(tlv); ds += len;

	*x1_len = ds;
	*x1 = calloc(ds,sizeof(unsigned char));
	memcpy(*x1,buffer,ds);

	return SKLOG_SUCCESS;
}

/*
 * encrypt blob that will be included in m1 message, using a random
 * session key k1 generated by T
 * 
 */
 
SKLOG_RETURN gen_e_k1(SKLOG_T_Ctx *t_ctx, unsigned char *k1,
	unsigned char *x1, unsigned int x1_len, unsigned char *x1_sign,
	unsigned int x1_sign_len, unsigned char **e_k1,
	unsigned int *e_k1_len)
 {
	#ifdef DO_TRACE
	DEBUG
	#endif

	//~
	//~ encrypt {x1|x1_signature} using session key
	//~

	unsigned char buffer[SKLOG_BUFFER_LEN] = { 0 };
	unsigned int ds = 0;

	unsigned char *tlv = 0;
	unsigned int len = 0;

	/**
	unsigned char *buffer2 = 0;
	unsigned int buffer2_len = x1_len + 8 +
							   x1_sign_len + 8;

	
	if ( SKLOG_alloc(&buffer2,unsigned char,buffer2_len) == SKLOG_FAILURE ) {
		ERROR("SKLOG_alloc() failure");
		return SKLOG_FAILURE;
	}
	*/


	//~ TLV-ize x1

	tlv_create_message(X1_BUF,x1_len,x1,&tlv,&len);
	memcpy(buffer+ds,tlv,len); free(tlv); ds += len;

	//~ TLV-ize x1_signature

	tlv_create_message(X1_SIGN_T,x1_sign_len,x1_sign,&tlv,&len);
	memcpy(buffer+ds,tlv,len); free(tlv); ds += len;

	if ( aes256_encrypt(buffer,ds,k1,SKLOG_SESSION_KEY_LEN,
						e_k1,e_k1_len) == SKLOG_FAILURE ) {
		ERROR("encrypt_aes256() failure")
		return SKLOG_FAILURE;
	}

	return SKLOG_SUCCESS;
}

/*
 * generate m1 message
 * 
 */
 
SKLOG_RETURN gen_m1(SKLOG_T_Ctx *t_ctx, SKLOG_PROTOCOL_STEP p,
	unsigned char *pke_u_k1, unsigned int pke_u_k1_len, 
	unsigned char *e_k1, unsigned int e_k1_len, unsigned char **m1,
	unsigned int *m1_len)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	unsigned char buffer[SKLOG_BUFFER_LEN] = { 0 };
	unsigned int ds = 0;

	unsigned int len = 0;
	unsigned char value[SKLOG_BUFFER_LEN] = { 0 };
	unsigned char *tlv = 0;

	//~ convert p in network order
	uint32_t p_net = htonl(p);

	/**
	//~ compose m1 in tlv format
	*m1_len = (sizeof(p_net) + 8) +
			  (t_ctx->t_id_len + 8) +
			  (pke_u_k1_len + 8) +
			  (e_k1_len + 8);

	if ( SKLOG_alloc(m1,unsigned char,*m1_len) == SKLOG_FAILURE ) {
		ERROR("SKLOG_alloc() failure");
		return SKLOG_FAILURE;
	}
	*/

	//~ TLV-ize p

	memcpy(value,&p_net,sizeof(p_net));
	tlv_create_message(PROTOCOL_STEP,sizeof(p_net),value,&tlv,&len);
	memcpy(buffer+ds,tlv,len); free(tlv); ds += len;
	memset(value,0,SKLOG_BUFFER_LEN);

	//~ TLV-ize t_id

	memcpy(value,t_ctx->t_id,t_ctx->t_id_len);
	tlv_create_message(ID_T,t_ctx->t_id_len,value,&tlv,&len);
	memcpy(buffer+ds,tlv,len); free(tlv); ds += len;
	memset(value,0,SKLOG_BUFFER_LEN);

	//~ TLV-ize pke_u_k1

	tlv_create_message(PKE_PUB_U,pke_u_k1_len,pke_u_k1,&tlv,&len);
	memcpy(buffer+ds,tlv,len); free(tlv); ds += len;

	//~ TLV-ize e_k1

	tlv_create_message(ENC_K1,e_k1_len,e_k1,&tlv,&len);
	memcpy(buffer+ds,tlv,len); free(tlv); ds += len;

	*m1_len = ds;
	*m1 = calloc(ds,sizeof(unsigned char));
	memcpy(*m1,buffer,ds);

	return SKLOG_SUCCESS;
}	

/*
 * send m1 message to U
 * 
 */
 
SKLOG_RETURN send_m1(SKLOG_T_Ctx *t_ctx, SKLOG_CONNECTION *conn,
	unsigned char *m1, unsigned int m1_len)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	unsigned char wbuf[SKLOG_BUFFER_LEN] = { 0 };
	unsigned int wlen = 0;

	unsigned char *tlv = 0;

	tlv_create_message(M1_MSG,m1_len,m1,&tlv,&wlen);
	memcpy(wbuf,tlv,wlen);
	
	write2file("out_m1_msg.dat", "w+", wbuf, wlen);
	
	#ifdef USE_BIO
	if ( BIO_write(conn->bio,wbuf,wlen) <= 0 ) {
		if ( !BIO_should_retry(conn->bio) ) {
			ERR_print_errors_fp(stderr);
			return SKLOG_FAILURE;
		}
		//~ to manage
	}
	#endif

	#ifdef USE_SSL
	if ( SSL_write(ssl,wbuf,wlen) < 0 ) {
		ERR_print_errors_fp(stderr);
		return SKLOG_FAILURE;
	}
	#endif

	return SKLOG_SUCCESS;
}
