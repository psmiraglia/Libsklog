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
#include "sklog_v.h"

#include <string.h>

#include <netinet/in.h>

#include <openssl/err.h>
#include <openssl/pem.h>

#include <openssl/evp.h>
#include <openssl/ssl.h>

/*
 * Create new context
 * 
 */
 
SKLOG_V_Ctx *
SKLOG_V_NewCtx (void)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	SKLOG_V_Ctx *tmp = 0;

	tmp = calloc(1, sizeof(SKLOG_V_Ctx));

	if ( tmp == NULL ) {
		ERROR("calloc() failure");
		return NULL;
	}

	memset(tmp, 0, sizeof(SKLOG_V_Ctx));

	return tmp;
}

/*
 * Initialize context
 * 
 */
 
SKLOG_RETURN
SKLOG_V_InitCtx (SKLOG_V_Ctx *ctx)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	/**
	 * NOTE
	 * 
	 * 	- get these information from config file
	 */
	 
	char *v_cert_path = SKLOG_DEF_V_CERT_PATH;
	char *v_privkey_path = SKLOG_DEF_V_RSA_KEY_PATH;

	FILE *fp = 0;

	int i = 0;
	
	/* check input parameters */
	
	if ( ctx == NULL ) {
		ERROR(MSG_BAD_INPUT_PARAMS);
		return SKLOG_FAILURE;
	}

	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	/* load certificate */
	
	ctx->v_cert = X509_new();
	
	fp = fopen(v_cert_path, "r");
	
	if ( fp != NULL ) {
		
		if ( !PEM_read_X509(fp, &ctx->v_cert, NULL,
			RSA_DEFAULT_PASSPHRASE) ) {
			ERR_print_errors_fp(stderr);
			goto error;
		}
		
		fclose(fp);
		
	} else {
		
		ERROR("Unable to open file %s", v_cert_path);
		goto error;
		
	}

	/* load private key */
	
	ctx->v_privkey = EVP_PKEY_new();
	
	fp = fopen(v_privkey_path, "r");
	
	if ( fp != NULL ) {
		
		if ( !PEM_read_PrivateKey(fp, &ctx->v_privkey, NULL, 
			RSA_DEFAULT_PASSPHRASE) ) {
			ERR_print_errors_fp(stderr);
			goto error;
		}
		
		fclose(fp);
		
	} else {
		
		ERROR("Unable to open file %s", v_privkey_path);
		goto error;
		
	}

	/* set t_address and t_port */
	
	memcpy(ctx->t_address, SKLOG_DEF_T_ADDRESS,
		strlen(SKLOG_DEF_T_ADDRESS));
		
	ctx->t_port = SKLOG_DEF_T_PORT;
	
	memcpy(ctx->t_cert_file_path, SKLOG_DEF_T_CERT_PATH, 
		strlen(SKLOG_DEF_T_CERT_PATH));

	/* set logfile list */
	
	for ( i = 0 ; i < BUF_4096 ; i++ )
		memset(ctx->verifiable_logfiles[i], 0, UUID_STR_LEN+1);

	ERR_free_strings();
	return SKLOG_SUCCESS;

error:
	ERR_free_strings();
	return SKLOG_FAILURE;
}

/*
 * Free context
 * 
 */
 
SKLOG_RETURN
SKLOG_V_FreeCtx (SKLOG_V_Ctx **ctx)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	/* check input parameters */
	
	if ( *ctx == NULL ) {
		ERROR(MSG_BAD_INPUT_PARAMS);
		return SKLOG_FAILURE;
	}
	
	X509_free((*ctx)->v_cert);
	
	EVP_PKEY_free((*ctx)->v_privkey);
	
	free(*ctx);
	
	*ctx = 0;

	return SKLOG_SUCCESS;
}

/*
 * Retrieve logfiles (deprecated)
 * 
 */
 
SKLOG_RETURN
SKLOG_V_RetrieveLogFiles (SKLOG_V_Ctx *ctx, SKLOG_CONNECTION *c)
{
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	//~ SKLOG_CONNECTION *c = 0;
	//~ int retval = 0;

	unsigned char rbuf[SKLOG_BUFFER_LEN] = { 0 };
	unsigned int rlen = 0;
	
	unsigned char wbuf[SKLOG_BUFFER_LEN] = { 0 };
	unsigned int wlen = 0;
	
	unsigned char *tlv = 0;
	unsigned char *value = 0;
	unsigned int len = 0;

	char list[SKLOG_BUFFER_LEN] = { 0 };
	char *token = 0;
	int index = 0;

	SSL_load_error_strings();

	//~ open connection
	//~ if ( ( c = new_connection()) == 0 ) {
		//~ ERROR("new_connection() failure");
		//~ goto error;
	//~ }

	//~ retval = setup_ssl_connection(c,ctx->t_address,ctx->t_port,
								  //~ ctx->v_cert,ctx->v_privkey,
								  //~ ctx->t_cert_file_path,DO_NOT_VERIFY);
//~ 
	//~ if ( retval == SKLOG_FAILURE ) {
		//~ ERROR("setup_ssl_connection() failure");
		//~ goto error;
	//~ }

	if ( tlv_create_message(RETR_LOG_FILES,0,NULL,&tlv,&wlen) == SKLOG_FAILURE ) {
		ERROR("tlv_create_message() failure");
		goto error;
	}
	memcpy(wbuf,tlv,wlen); free(tlv);

	write2file("v_out_retrieve.dat", "a+", wbuf, wlen);
	
	#ifdef USE_BIO
	if ( BIO_write(c->bio,wbuf,wlen) <= 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}
	 
	rlen = BIO_read(c->bio,rbuf,SKLOG_BUFFER_LEN);

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
	
	 
	rlen = SSL_read(c->ssl,rbuf,SKLOG_BUFFER_LEN);
	if ( rlen <= 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}
	#endif
	
	write2file("v_in_retrieve.dat", "a+", rbuf, rlen);

	//~ close connection
	//~ destroy_ssl_connection(c);
	//~ free_conenction(c);

	SKLOG_TLV_TYPE type = 0;
	tlv_get_type(rbuf,&type);

	switch ( type ) {
		case LOG_FILES:
			#ifdef DO_TRACE
			NOTIFY("Received LOG_FILES");
			#endif

			if ( tlv_parse_message(rbuf,LOG_FILES,NULL,&len,&value) == SKLOG_FAILURE ) {
				ERROR("tlv_parse_message() failure");
				goto error;
			}

			memcpy(list,value,len); free(value);
			token = strtok(list,";");

			while ( token != NULL ) {

				strncpy(ctx->verifiable_logfiles[index++],token,UUID_STR_LEN);
				token = strtok(NULL,";");
				NOTIFY("OK - %d", index);
			}
			
			break;
		default:
			NOTIFY("Protocol Error");
			break;
	}

	NOTIFY("I'm here...");
	ctx->verifiable_logfiles_size = index;
	ERR_free_strings();
	return SKLOG_SUCCESS;

error:
	//~ close connection
	//~ destroy_ssl_connection(c);
	//~ free_conenction(c);
	
	ERR_free_strings();
	return SKLOG_FAILURE;
}

/*
 * Retrieve logfiles
 * 
 */
 
int
retrieve (SKLOG_V_Ctx *ctx, unsigned char *rbuf, size_t *rlen,
		  size_t rlen_max, unsigned char *wbuf, size_t *wlen)
{
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	int rv = 0;
	
	SKLOG_CONNECTION *conn = 0;
	
	int nread = 0;
	int nwrite = 0;
	
	/* open connection */
	
	conn = SKLOG_CONNECTION_New();
	
	if ( conn == NULL ) {
		ERROR("SKLOG_CONNECTION_New() failure");
		return SKLOG_FAILURE;
	}

	rv = SKLOG_CONNECTION_Init(conn, ctx->t_address,
		ctx->t_port, ctx->v_cert, ctx->v_privkey,
		ctx->t_cert_file_path, DO_NOT_VERIFY);
	            
	if ( rv == SKLOG_FAILURE ) {
		ERROR("SKLOG_CONNECTION_Init() failure");
		return SKLOG_FAILURE;
	}
	
	/* doit */
	
	SSL_load_error_strings();
	
	nwrite = SSL_write(conn->ssl, wbuf, *wlen);
	
	if ( nwrite <= 0 ) {
		ERROR("SSL_write() failure");
		ERR_print_errors_fp(stderr);
		return SKLOG_FAILURE;
	}
	
	nread = SSL_read(conn->ssl, rbuf, rlen_max);
	
	if ( nwrite <= 0 ) {
		ERROR("SSL_read() failure");
		ERR_print_errors_fp(stderr);
		return SKLOG_FAILURE;
	}
	
	*rlen = nread;
	
	ERR_free_strings();
	
	/* close connection */
	
	rv = SKLOG_CONNECTION_Destroy(conn);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("SKLOG_CONNECTION_Destroy() failure");
		return SKLOG_FAILURE;
	}
	
	rv = SKLOG_CONNECTION_Free(&conn);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("SKLOG_CONNECTION_Free() failure");
		return SKLOG_FAILURE;
	}
	
	return SKLOG_SUCCESS;
}
 
SKLOG_RETURN
SKLOG_V_RetrieveLogFiles_v2 (SKLOG_V_Ctx *ctx,
							 sklog_data_tranfer_cb retrieve_cb)
{
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	int rv = SKLOG_SUCCESS;
	
	char buf[BUF_8192+1] = { 0x0 };
	char *id = 0;
	int i = 0;
	
	unsigned char wbuf[BUF_8192+1] = { 0x0 };
	unsigned int wlen = 0;
	
	unsigned char rbuf[BUF_8192+1] = { 0x0 };
	unsigned int rlen = 0;
	
	unsigned char *tlv = 0;
	unsigned int tlv_type = 0;
	unsigned char *tlv_value = 0;
	unsigned int tlv_len = 0;
	
	/* check input arguments */
	
	if ( ctx == NULL || retrieve_cb == NULL ) {
		ERROR(MSG_BAD_INPUT_PARAMS);
		return SKLOG_FAILURE;
	}
	
	rv = tlv_create_message(RETR_LOG_FILES, 0, 0, &tlv, &wlen);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("tlv_create_message() failure");
		return SKLOG_FAILURE;
	}
	
	memcpy(wbuf, tlv, wlen);
	free(tlv);
	
	rv = retrieve_cb(ctx, rbuf, (size_t *) &rlen, BUF_8192, wbuf,
		(size_t *) &wlen);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("retrieve_cb() failure")
		return SKLOG_FAILURE;
	}
	
	rv = tlv_get_type(rbuf, &tlv_type);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("tlv_get_type() failure");
		return SKLOG_FAILURE;
	}
	
	switch ( tlv_type ) {
		case LOG_FILES:
		
			rv = tlv_get_value(rbuf, &tlv_value);
			
			if ( rv == SKLOG_FAILURE ) {
				ERROR("tlv_get_value() failure");
				return SKLOG_FAILURE;
			}
			
			rv = tlv_get_len(rbuf, &tlv_len);
			
			if ( rv == SKLOG_FAILURE ) {
				ERROR("tlv_get_len() failure");
				free(tlv_value);
				return SKLOG_FAILURE;
			}
			
			memcpy(buf, tlv_value, tlv_len);
			free(tlv_value);
			
			id = strtok(buf, ";");
			
			while ( id != NULL ) {
				memcpy(ctx->verifiable_logfiles[i++], id, UUID_STR_LEN);
				id = strtok(NULL, ";");
			}
			
			ctx->verifiable_logfiles_size = i;
			
			rv = SKLOG_SUCCESS;
			break;
			
		default:
			ERROR("Protocol error");
			rv = SKLOG_FAILURE;
			break;
	}
	
	
	return rv;
}

/*
 * Verify logfile (deprecated)
 *  
 */
 
SKLOG_RETURN
SKLOG_V_VerifyLogFile (SKLOG_V_Ctx *ctx, SKLOG_CONNECTION *c,
					   unsigned int logfile_id)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	unsigned char wbuf[SKLOG_BUFFER_LEN] = { 0 };
	unsigned int wlen = 0;
	
	unsigned char rbuf[SKLOG_BUFFER_LEN] = { 0 };
	unsigned int rlen = 0;

	SKLOG_TLV_TYPE type = NOTYPE;
	unsigned int len = 0;
	unsigned char value[SKLOG_BUFFER_LEN] = { 0 };
	unsigned char *tlv = 0;

	char inbuf[INBUF_LEN] = {0};
	int id = 0;

	int retval = SKLOG_SUCCESS;

	SSL_load_error_strings();

	id = logfile_id;

	while ( strlen((ctx)->verifiable_logfiles[id]) <= 0 ) {
		ERROR("Invalid logfile_id");
		fprintf(stdout,"Select logfile id: ");
		memset(inbuf,0,INBUF_LEN);
		if ( gets(inbuf) != NULL )
			sscanf(inbuf,"%d",&id);
	}
	
	memcpy(value,(ctx)->verifiable_logfiles[logfile_id],UUID_STR_LEN);
	len = UUID_STR_LEN;

	//~ send: [VERIFY_LOGFILE][UUID_STR_LEN][UUID]

	if ( tlv_create_message(VERIFY_LOGFILE,len,value,&tlv,&wlen) == SKLOG_FAILURE ) {
		ERROR("tlv_create_message() failure");
		goto error;
	}
	memcpy(wbuf,tlv,wlen);

	write2file("v_out_verify.dat", "w+", wbuf, wlen);
	
	#ifdef USE_BIO
	if ( BIO_write(c->bio,wbuf,wlen) <= 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}
	
	rlen = BIO_read(c->bio,rbuf,SKLOG_BUFFER_LEN);

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
	
	rlen = SSL_read(c->ssl,rbuf,SKLOG_BUFFER_LEN);

	if ( rlen <= 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}
	#endif
	
	write2file("v_in_verify.dat", "w+", rbuf, rlen);

	tlv_get_type(rbuf,&type);

	switch ( type ) {
		case VERIFY_LOGFILE_SUCCESS:
			#ifdef DO_TRACE
			NOTIFY("Logfile verification successful");
			#endif
			break;
		case VERIFY_LOGFILE_FAILURE:
			#ifdef DO_TRACE
			NOTIFY("Logfile verification fails");
			#endif
			retval = SKLOG_FAILURE;
			break;
		default:
			ERROR("Protocol Error");
			retval = SKLOG_FAILURE;
			break;
	} 
	
	ERR_free_strings();
	return retval;

error:
	ERR_free_strings();
	return SKLOG_FAILURE;
}

/*
 * Verify logfile
 *  
 */
 
int
verify (SKLOG_V_Ctx *ctx, unsigned char *rbuf, size_t *rlen,
	    size_t rlen_max, unsigned char *wbuf, size_t *wlen)
{
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	int rv = SKLOG_SUCCESS;
	
	int nwrite = 0;
	int nread = 0;
	
	SKLOG_CONNECTION *conn = 0;
	
	/* open connection */
	
	conn = SKLOG_CONNECTION_New();
                
	if ( conn == NULL ) {
		ERROR("SKLOG_CONNECTION_New() failure");
		return SKLOG_FAILURE;
	}

	rv = SKLOG_CONNECTION_Init(conn, ctx->t_address, ctx->t_port,
		ctx->v_cert, ctx->v_privkey, ctx->t_cert_file_path,
		DO_NOT_VERIFY);
	            
	if ( rv == SKLOG_FAILURE ) {
		ERROR("SKLOG_CONNECTION_Init() failure");
		return SKLOG_FAILURE;
	}
	
	/* doit */
	
	SSL_load_error_strings();
	
	nwrite = SSL_write(conn->ssl, wbuf, *wlen);
	
	if ( nwrite <= 0 ) {
		ERROR("SSL_write() failure");
		ERR_print_errors_fp(stderr);
		return SKLOG_FAILURE;
	}
	
	nread = SSL_read(conn->ssl, rbuf, rlen_max);
	
	if ( nwrite <= 0 ) {
		ERROR("SSL_read() failure");
		ERR_print_errors_fp(stderr);
		return SKLOG_FAILURE;
	}
	
	*rlen = nread;
	
	ERR_free_strings();
	
	/* close connection */
	
	rv = SKLOG_CONNECTION_Destroy(conn);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("SKLOG_CONNECTION_Destroy() failure");
		return SKLOG_FAILURE;
	}
	
	rv = SKLOG_CONNECTION_Free(&conn);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("SKLOG_CONNECTION_Free() failure");
		return SKLOG_FAILURE;
	}
	
	return SKLOG_SUCCESS;
}
 
SKLOG_RETURN
SKLOG_V_VerifyLogFile_v2 (SKLOG_V_Ctx *ctx, char *logfile_id,
						  sklog_data_tranfer_cb verify_cb)
{
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	int rv = SKLOG_SUCCESS;
	
	unsigned char wbuf[BUF_8192+1] = { 0x0 };
	unsigned int wlen = 0;
	
	unsigned char rbuf[BUF_8192+1] = { 0x0 };
	unsigned int rlen = 0;
	
	unsigned char *tlv = 0;
	unsigned int tlv_type = 0;
	//~ unsigned int tlv_len = 0;
	//~ unsigned char *tlv_value = 0;
	
	/* check input parameters */
	
	if ( ctx == NULL || logfile_id == NULL || verify_cb == NULL ) {
		ERROR(MSG_BAD_INPUT_PARAMS);
		return SKLOG_FAILURE;
	}
	
	/* create message */

	rv = tlv_create_message(VERIFY_LOGFILE, strlen(logfile_id),
		(unsigned char *)logfile_id, &tlv, &wlen);
		
	if ( rv == SKLOG_FAILURE ) {
		ERROR("tlv_create_message() failure");
		return SKLOG_FAILURE;
	}
	
	memcpy(wbuf, tlv, wlen);
	free(tlv);
	
	/* ---------- */
	/*  callback  */
	
	rv = verify_cb(ctx, rbuf, (size_t *)&rlen, BUF_8192, wbuf,
		(size_t *)&wlen);
		
	/* ---------- */
	
	rv = tlv_get_type(rbuf, &tlv_type);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("tlv_get_type() failure");
		return SKLOG_FAILURE;
	}
	
	switch ( tlv_type ) {
		case VERIFY_LOGFILE_SUCCESS:
			NOTIFY("Logfile verification successful");
			rv = SKLOG_SUCCESS;
			break;
			
		case VERIFY_LOGFILE_FAILURE:
			NOTIFY("Logfile verification fails");
			rv = SKLOG_FAILURE;
			break;
			
		default:
			ERROR("Protocol Error");
			rv = SKLOG_FAILURE;
			break;
	}
	
	return rv;
}
 
/*
 * Verify logfile
 */
 
SKLOG_RETURN
SKLOG_V_VerifyLogFile_uuid (SKLOG_V_Ctx *ctx, SKLOG_CONNECTION *c,
						    char *logfile_id)
{
	#ifdef DO_TRACE
	DEBUG
	#endif

	unsigned char wbuf[SKLOG_BUFFER_LEN] = { 0 };
	unsigned int wlen = 0;
	
	unsigned char rbuf[SKLOG_BUFFER_LEN] = { 0 };
	unsigned int rlen = 0;

	SKLOG_TLV_TYPE type = NOTYPE;
	unsigned int len = 0;
	unsigned char value[SKLOG_BUFFER_LEN] = { 0 };
	unsigned char *tlv = 0;

	//~ char inbuf[INBUF_LEN] = {0};
	//~ int id = 0;

	int retval = SKLOG_SUCCESS;

	SSL_load_error_strings();

	/**
	int i = 0;
	int j = 0;

	memcpy(value+i,logfile_id+j,8); value[8]='-';
	i = 9; j+=8;
	memcpy(value+i,logfile_id+j,4); value[13]='-';
	i = 14; j+=4;
	memcpy(value+i,logfile_id+j,4); value[18]='-';
	i = 19; j+=4;
	memcpy(value+i,logfile_id+j,4); value[23]='-';
	i = 24; j+=4;
	memcpy(value+i,logfile_id+j,12);
	**/
	
	//~ memcpy(value,logfile_id,UUID_STR_LEN);
	memcpy(value,logfile_id,SKLOG_UUID_STR_LEN);
	len = SKLOG_UUID_STR_LEN;

	//~ send: [VERIFY_LOGFILE][UUID_STR_LEN][UUID]

	if ( tlv_create_message(VERIFY_LOGFILE,len,value,&tlv,&wlen) == SKLOG_FAILURE ) {
		ERROR("tlv_create_message() failure");
		goto error;
	}
	memcpy(wbuf,tlv,wlen);

	#ifdef USE_BIO
	if ( BIO_write(c->bio,wbuf,wlen) <= 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}
	
	rlen = BIO_read(c->bio,rbuf,SKLOG_BUFFER_LEN);

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
	
	rlen = SSL_read(c->ssl,rbuf,SKLOG_BUFFER_LEN);

	if ( rlen <= 0 ) {
		ERR_print_errors_fp(stderr);
		goto error;
	}
	#endif

	tlv_get_type(rbuf,&type);

	switch ( type ) {
		case VERIFY_LOGFILE_SUCCESS:
			#ifdef DO_TRACE
			NOTIFY("Logfile verification successful");
			#endif
			break;
		case VERIFY_LOGFILE_FAILURE:
			#ifdef DO_TRACE
			NOTIFY("Logfile verification fails");
			#endif
			retval = SKLOG_FAILURE;
			break;
		default:
			ERROR("Protocol Error");
			retval = SKLOG_FAILURE;
			break;
	} 
	
	ERR_free_strings();
	return retval;

error:
	ERR_free_strings();
	return SKLOG_FAILURE;
}
