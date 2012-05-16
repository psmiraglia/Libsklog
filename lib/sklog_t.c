/*
**    Copyright (C) 2011 Politecnico di Torino, Italy
**
**        TORSEC group -- http://security.polito.it
**        Author: Paolo Smiraglia <paolo.smiraglia@polito.it>
**
**    This file is part of Libsklog.
**
**    Libsklog is free software: you can redistribute it and/or modify
**    it under the terms of the GNU General Public License as published by
**    the Free Software Foundation; either version 2 of the License, or
**    (at your option) any later version.
**
**    Libsklog is distributed in the hope that it will be useful,
**    but WITHOUT ANY WARRANTY; without even the implied warranty of
**    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**    GNU General Public License for more details.
**
**    You should have received a copy of the GNU General Public License
**    along with Libsklog.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "sklog_internal.h"
#include "sklog_t.h"

#ifdef USE_FILE
    #include "storage/sklog_file.h"
#elif USE_SYSLOG
    #include "storage/sklog_syslog.h"
#elif USE_SQLITE
    #include "storage/sklog_sqlite.h"
#else
    #include "storage/sklog_dummy.h"
    #include "storage/sklog_sqlite.h"
#endif

#include <signal.h>

#include <sys/wait.h>

#include <openssl/rand.h>

#include <arpa/inet.h>

/*
 * create new (not initialized) T context
 * 
 */

SKLOG_T_Ctx* SKLOG_T_NewCtx(void)
{
    #ifdef DO_TRACE
    DEBUG
    #endif
    
    SKLOG_T_Ctx *ctx = calloc(1,sizeof(SKLOG_T_Ctx));

    if ( ctx == NULL ) {
        ERROR("calloc() failure");
        return NULL;
    }

    memset(ctx,0,sizeof(SKLOG_T_Ctx));
    
    ctx->lsdriver = calloc(1,sizeof(SKLOG_T_STORAGE_DRIVER));

    if ( ctx->lsdriver == NULL ) {
        ERROR("calloc() failure");
        return NULL;
    }

    #ifdef USE_FILE
    ctx->lsdriver->store_authkey =     &sklog_file_t_store_authkey;
    ctx->lsdriver->store_m0_msg =      &sklog_file_t_store_m0_msg;
    ctx->lsdriver->store_logentry =    &sklog_file_t_store_logentry;
    #elif USE_SYSLOG
    ctx->lsdriver->store_authkey =     &sklog_syslog_t_store_authkey;
    ctx->lsdriver->store_m0_msg =      &sklog_syslog_t_store_m0_msg;
    ctx->lsdriver->store_logentry =    &sklog_syslog_t_store_logentry;
    #elif USE_SQLITE
    ctx->lsdriver->store_authkey =     &sklog_sqlite_t_store_authkey;
    ctx->lsdriver->store_m0_msg =      &sklog_sqlite_t_store_m0_msg;
    ctx->lsdriver->store_logentry =    &sklog_sqlite_t_store_logentry;
    ctx->lsdriver->retrieve_logfiles = &sklog_sqlite_t_retrieve_logfiles;
    ctx->lsdriver->verify_logfile =    &sklog_sqlite_t_verify_logfile;
    #else
    ctx->lsdriver->store_authkey =     &sklog_sqlite_t_store_authkey;
    ctx->lsdriver->store_m0_msg =      &sklog_sqlite_t_store_m0_msg;
    ctx->lsdriver->store_logentry =    &sklog_sqlite_t_store_logentry;
    ctx->lsdriver->retrieve_logfiles = &sklog_sqlite_t_retrieve_logfiles;
    ctx->lsdriver->verify_logfile =    &sklog_sqlite_t_verify_logfile;
    #endif

    return ctx;
}

/*
 * free T context
 * 
 */
 
SKLOG_RETURN SKLOG_T_FreeCtx(SKLOG_T_Ctx **ctx)
{
    #ifdef DO_TRACE
    DEBUG
    #endif
    
    if ( *ctx == NULL ) {
		ERROR("argument 1 must be not null");
		return SKLOG_FAILURE;
	}

    X509_free((*ctx)->t_cert);
    EVP_PKEY_free((*ctx)->t_privkey);

    memset(*ctx,0,sizeof(SKLOG_T_Ctx));
    *ctx = 0;
    
    return SKLOG_SUCCESS;
}

/*
 * initialze T context
 * 
 */
 
SKLOG_RETURN SKLOG_T_InitCtx(SKLOG_T_Ctx *t_ctx)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    SKLOG_RETURN retval = SKLOG_SUCCESS;

    FILE *fp = NULL;

    char t_cert[SKLOG_SETTING_VALUE_LEN] = { 0 };
    char t_privkey[SKLOG_SETTING_VALUE_LEN] = { 0 };
    char t_privkey_passphrase[SKLOG_SETTING_VALUE_LEN] = { 0 };
    char t_id[SKLOG_SETTING_VALUE_LEN] = { 0 };
    char t_address[SKLOG_SETTING_VALUE_LEN] = { 0 };
    int t_port = 0;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    if ( t_ctx == NULL ) {
        ERROR("t_ctx must be not null");
        goto error;
    }    

    /* parse configuration file */

    retval = parse_t_config_file(t_cert, t_privkey, t_privkey_passphrase,
		t_id, t_address, &t_port);

    if ( retval == SKLOG_FAILURE ) {
        ERROR("parse_config_file() failure");
        goto error;
    }

    /* load t_id */
    
    t_ctx->t_id_len = strlen(t_id);
    snprintf(t_ctx->t_id,HOST_NAME_MAX,"%s",t_id); //~ Bugfix: Sebastian Banescu <banescusebi@gmail.com>

    /* load T's X509 certificate */
    
    memcpy(t_ctx->t_cert_file_path, t_cert, strlen(t_cert));
    t_ctx->t_cert = 0;
    
    if ( (fp = fopen(t_cert, "r")) != NULL ) {
        if ( !PEM_read_X509(fp, &t_ctx->t_cert, NULL, NULL) ) {
            ERR_print_errors_fp(stderr);
            goto error;
        }
        fclose(fp); fp = 0;
    } else {
        ERROR("Unable to read file %s", t_cert)
        goto error;
    }
    
    /* load T's rsa privkey */
    
    memcpy(t_ctx->t_privkey_file_path, t_privkey, strlen(t_privkey));
    t_ctx->t_privkey = EVP_PKEY_new();
    
    if ( (fp = fopen(t_privkey, "r")) != NULL ) {
        if ( !PEM_read_PrivateKey(fp, &t_ctx->t_privkey, NULL, 
			RSA_DEFAULT_PASSPHRASE) ) {
            ERROR("PEM_read_PrivateKey() failure")
            goto error;
        }
        fclose(fp); fp = 0;
    } else {
        ERROR("unable to read file %s", t_privkey)
        goto error;
    }

    /* load binding information */
    
    memcpy(t_ctx->t_address, t_address, strlen(t_address));
    t_ctx->t_port = t_port;

    ERR_free_strings();
    return SKLOG_SUCCESS;

error:
    if ( fp > 0 ) fclose(fp);
    ERR_free_strings();
    return SKLOG_FAILURE;
}

/*
 * manage new logging session requests
 * 
 */
 
SKLOG_RETURN SKLOG_T_ManageLoggingSessionInit(SKLOG_T_Ctx *t_ctx,
	unsigned char *m0, unsigned int m0_len, char *u_address,
	unsigned char **m1, unsigned int *m1_len)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    SKLOG_PROTOCOL_STEP p = 0;
    
    uuid_t logfile_id;

    unsigned char *e_k0 = 0;
    unsigned int e_k0_len = 0;
    unsigned char *pke_t_k0 = 0;
    unsigned int pke_t_k0_len = 0;
    
    unsigned char *k0 = 0;
    unsigned int k0_len = 0;

    unsigned char *plain = 0;
    unsigned int plain_len = 0;

    unsigned char *x0 = 0;
    unsigned int x0_len = 0;
    unsigned char *x0_sign = 0;
    unsigned int x0_sign_len = 0;

    X509 *u_cert = 0;
    unsigned char auth_key[SKLOG_AUTH_KEY_LEN] = { 0 };

    unsigned char *x1 = 0;
    unsigned int x1_len = 0;

    unsigned char k1[SKLOG_SESSION_KEY_LEN] = { 0 };

    unsigned char *x1_sign = 0;
    unsigned int x1_sign_len = 0;

    unsigned char *e_k1 = 0;
    unsigned int e_k1_len = 0;

    unsigned char *pke_u_k1 = 0;

    unsigned char *m1_tmp = 0;
    unsigned int m1_tmp_len = 0;
    
    if ( t_ctx == NULL ) {
		ERROR("argument 1 must be not NULL");
		return SKLOG_FAILURE;
	}
	
	if ( m0 == NULL ) {
		ERROR("argument 2 must be not NULL");
		return SKLOG_FAILURE;
	}
	
	if ( u_address == NULL ) {
		ERROR("argument 4 must be not NULL");
		return SKLOG_FAILURE;
	}

    write2file("notest/t_in_m0_msg.dat", "w+", m0, m0_len);
    
    if ( parse_m0(t_ctx,m0,m0_len,&p,&logfile_id,&pke_t_k0,
                  &pke_t_k0_len,&e_k0,&e_k0_len) == SKLOG_FAILURE ) {
        ERROR("parse_m0() failure")
        goto error;
    }
    
    write2file("notest/t_logfileid_from_m0.dat", "w+", logfile_id, 16);
    
    #ifdef DO_TESTS
    write2file("data/logfileid.dat", "w+", logfile_id, 16);
    #endif
    
    //~ store m0_msg
    if ( t_ctx->lsdriver->store_m0_msg(u_address, logfile_id, m0, m0_len) == SKLOG_FAILURE ) {
        ERROR("store_m0_msg() failure");
        goto error;
    }
    
    SKLOG_free(&m0); // PS: to check

    //~ decrypt k0 using T's private key
    size_t len = 0;
    if ( pke_decrypt(t_ctx->t_privkey,pke_t_k0,
                     pke_t_k0_len,&k0,&len) == SKLOG_FAILURE ) {
        ERROR("pke_decrypt() failure")
        goto error; //~ m0 verification fails
    }
    k0_len = len;
    
    if ( k0_len != SKLOG_SESSION_KEY_LEN ) {
		fprintf(stderr,"Somethings goes wrong: key len is %d\n",k0_len);
		goto error;
	}
	
    SKLOG_free(&pke_t_k0);

    if ( aes256_decrypt(e_k0,e_k0_len,k0,SKLOG_SESSION_KEY_LEN,&plain,
                        &plain_len) == SKLOG_FAILURE ) {
        ERROR("decrypt_aes256() failure")
        goto error; //~ m0 verification fails
    }
    SKLOG_free(&e_k0);
    SKLOG_free(&k0);

    //~ parse plain
    if ( parse_e_k0_content(plain,plain_len,&x0,&x0_len,
                            &x0_sign,&x0_sign_len) == SKLOG_FAILURE ) {
        ERROR("parse_plain() failure")
        goto error;
    }
    SKLOG_free(&plain);

    //~ parse x0
    if ( parse_x0(x0,x0_len,&u_cert,auth_key) == SKLOG_FAILURE ) {
        ERROR("parse_x0() failure")
        goto error;
    }

    /*----------------------------------------------------------------*/
    
    /**
     * M0 Verification
     *
     * The M0 message verification may include multiple steps which are
     * not specified. In the paper, authors suggest as verification
     * steps only the signature and certificate verification.
     *
     * Users may define a custom verification steps list.
     */

    //~ verify U's signature
    if ( verify_m0_signature(u_cert,x0_sign,x0_sign_len,
                                        x0,x0_len) == SKLOG_FAILURE ) {
        ERROR("verify_m0_signature() failure")
        goto error;
    }
    SKLOG_free(&x0_sign);

    //~ check validity of U's certificate
    if ( verify_m0_certificate(u_cert) == SKLOG_FAILURE ) {
        ERROR("verify_m0_certificate() failure")
        goto error;
    }
    
    /*----------------------------------------------------------------*/

    //~ store auth_key
    if ( t_ctx->lsdriver->store_authkey(u_address,logfile_id,
                                         auth_key) == SKLOG_FAILURE ) {
        ERROR("store_auth_key() failure")
        goto error;
    }
    
    //~ remove auth_key from memory
    memset(auth_key,0,SKLOG_AUTH_KEY_LEN); 

    /*----------------------------------------------------------------*/
    /*----------------------------------------------------------------*/

    //~ generate x1
    if ( gen_x1(&p,x0,x0_len,&x1,&x1_len) == SKLOG_FAILURE ) {
        ERROR("gen_x1() failure")
        goto error;
    }
    SKLOG_free(&x0);

    //~ generate a random session key k1
    RAND_bytes(k1,SKLOG_SESSION_KEY_LEN);

    //~ sign x1 using T's private key
    if ( sign_message(x1,x1_len,t_ctx->t_privkey,
                      &x1_sign,&x1_sign_len) == SKLOG_FAILURE ) {
        ERROR("sign_message() failure")
        goto error;
    }

    //~ encrypt {x1,x1_sign} using k1 key
    if ( gen_e_k1(t_ctx,k1,x1,x1_len,x1_sign,x1_sign_len,
                  &e_k1,&e_k1_len) == SKLOG_FAILURE ) {
        ERROR("gen_e_k1() failure")
        goto error;
    }
    SKLOG_free(&x1_sign);
    SKLOG_free(&x1);

    //~ encrypt k1 using U's public key
    size_t pke_u_k1_len = 0;
    if ( pke_encrypt(u_cert,k1,SKLOG_SESSION_KEY_LEN,
                     &pke_u_k1,&pke_u_k1_len) == SKLOG_FAILURE ) {
        ERROR("pke_encrypt() failure")
        goto error;
    }
    X509_free(u_cert);
    memset(k1,0,SKLOG_SESSION_KEY_LEN);
    
    //~ generate m1
    if ( gen_m1(t_ctx,p,pke_u_k1,pke_u_k1_len,e_k1,
                e_k1_len,&m1_tmp,&m1_tmp_len) == SKLOG_FAILURE ) {
        ERROR("gen_m1() failure")
        goto error;
    }
    SKLOG_free(&e_k1);
    SKLOG_free(&pke_u_k1);

    *m1 = m1_tmp;
    *m1_len = m1_tmp_len;
    
    //~ SHOWBUF("M1MSG", m1_tmp, m1_tmp_len);
    write2file("notest/t_out_m1_msg.dat", "w+", m1_tmp, m1_tmp_len);
    
    return SKLOG_SUCCESS;

error:
    if ( pke_t_k0 > 0 )    SKLOG_free(&pke_t_k0);
    if ( e_k0 > 0 )        SKLOG_free(&e_k0);
    if ( k0 > 0 )          SKLOG_free(&k0);
    if ( plain > 0 )       SKLOG_free(&plain);
    if ( x0 > 0 )          SKLOG_free(&x0);
    if ( x0_sign > 0 )     SKLOG_free(&x0_sign);
    if ( u_cert )      X509_free(u_cert);
    if ( x1 > 0 )          SKLOG_free(&x1);
    if ( x1_sign > 0 )     SKLOG_free(&x1_sign);
    if ( e_k1 > 0 )        SKLOG_free(&e_k1);
    if ( pke_u_k1 > 0 )    SKLOG_free(&pke_u_k1);

    return SKLOG_FAILURE;
}

/*
 * manage logfile upload requests
 * 
 */
 
SKLOG_RETURN SKLOG_T_ManageLogfileUpload(SKLOG_T_Ctx *t_ctx,
	SKLOG_CONNECTION *c)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    unsigned char *tlv = 0;
    unsigned int len = 0;
    unsigned char *value = 0;

    unsigned char wbuf[SKLOG_BUFFER_LEN] = { 0 };
    unsigned int wlen = 0;
    
    unsigned char rbuf[SKLOG_BUFFER_LEN] = { 0 };
    unsigned int rlen = 0;

    int more = 1;
    int error = 0;

    SKLOG_TLV_TYPE type = 0;
    
    if ( t_ctx == NULL ) {
		ERROR("argument 1 must be not NULL");
		return SKLOG_FAILURE;
	}

    SSL_load_error_strings();
    
    if ( tlv_create_message(LOGFILE_UPLOAD_READY,0,NULL,&tlv,&len) == SKLOG_FAILURE ) {
        ERROR("tlv_create_message() failure");
        goto error;
    }

    memcpy(wbuf,tlv,len);
    wlen = len;


	write2file("notest/t_out_upload.dat", "w+", wbuf, wlen);
	
	#ifdef DO_TESTS
		;
	#else
    #ifdef USE_BIO
    if ( BIO_write(c->bio,wbuf,wlen) <= 0 ) {
            ERR_print_errors_fp(stderr);
            return SKLOG_FAILURE;
    }
    #endif

    #ifdef USE_SSL
    if ( SSL_write(c->ssl,wbuf,wlen) <= 0 ) {
            ERR_print_errors_fp(stderr);
            return SKLOG_FAILURE;
    }
    #endif
    #endif
    
    memset(wbuf,0,SKLOG_BUFFER_LEN); wlen=0;

	#ifdef DO_TESTS
	FILE *fp_in = 0;
	char b64[SKLOG_BUFFER_LEN] = { 0 };
	unsigned char *b64blob = 0;
	unsigned int b64blob_len = 0;
	
	fp_in = fopen("data/SKLOG_T_ManageLogfileUpload_in.dat", "r");
	if ( fp_in == NULL ) {
		ERROR("Unable to open file data/SKLOG_T_ManageLogfileUpload_in.dat");
		exit(1);
	}
	#endif

    while ( more ) {
		#ifdef DO_TESTS
		
		fscanf(fp_in, "%s", b64);
		b64_dec(b64, strlen(b64), &b64blob, &b64blob_len);
		
		memcpy(rbuf, b64blob, b64blob_len);
		free(b64blob);
		memset(b64, 0, SKLOG_BUFFER_LEN);
		
		if ( rlen == 0 ) ;
		
		#else
		
        #ifdef USE_BIO
        if ( (rlen = BIO_read(c->bio,rbuf,SKLOG_BUFFER_LEN)) <= 0 ) {
                ERR_print_errors_fp(stderr);
                return SKLOG_FAILURE;
        }
        #endif
        #ifdef USE_SSL
        if ( (rlen = SSL_read(c->ssl,rbuf,SKLOG_BUFFER_LEN)) <= 0 ) {
                ERR_print_errors_fp(stderr);
                return SKLOG_FAILURE;
        }
        #endif
        
        write2file("notest/t_in_upload.dat", "a+", rbuf, rlen);
        
        #endif
        
        if ( tlv_get_type(rbuf,&type) == SKLOG_FAILURE ) {
            ERROR("tlv_get_type() failure");
            goto error;
        }

        switch ( type ) {
            case UPLOAD_LOGENTRY:
		        
                //~ NOTIFY("Received log entry");

                if ( tlv_parse_message(rbuf,NOTYPE,NULL,&len,&value) == SKLOG_FAILURE ) {
                    ERROR("tlv_parse_message() failure")
                    goto error;
                }

                if ( t_ctx->lsdriver->store_logentry(value,len) == SKLOG_FAILURE ) {
                    ERROR("t_ctx->lsdriver->store_logentry() failure");
                    goto error;
                }

                if ( tlv_create_message(UPLOAD_LOGENTRY_ACK,0,NULL,&tlv,&len) == SKLOG_FAILURE ) {
                    ERROR("tlv_create_message() failure");
                    goto error;
                }
                memcpy(wbuf,tlv,len); wlen = len;

				write2file("notest/t_out_upload.dat", "a+", wbuf, wlen);

				#ifdef DO_TESTS
					;
				#else
                #ifdef USE_BIO
                if ( BIO_write(c->bio,wbuf,wlen) <= 0 ) {
                        ERR_print_errors_fp(stderr);
                        return SKLOG_FAILURE;
                }
                #endif
                #ifdef USE_SSL
                if ( SSL_write(c->ssl,wbuf,wlen) <= 0 ) {
                        ERR_print_errors_fp(stderr);
                        return SKLOG_FAILURE;
                }
                #endif
                #endif
                
                break;
            case LOGFILE_UPLOAD_END:
		        #ifdef DO_TRACE
                NOTIFY("Logfile Upload Terminated");
                #endif
                more = 0;
                break;
            default:
                ERROR("Protocol Error");
                fprintf(stderr, ">>> 0x%8.8x | 0x%8.8x\n", type, LOGFILE_UPLOAD_END);
                error = 1;
                break;
        }

        if ( error ) 
            goto error;
    } //~ while
    
    #ifdef DO_TESTS
    fclose(fp_in);
    #endif
    
    ERR_free_strings();
    return SKLOG_SUCCESS;

error:
    ERR_free_strings();
    return SKLOG_FAILURE;
}

/*
 * manage logfiles retrieve requests
 * 
 */
 
SKLOG_RETURN SKLOG_T_ManageLogfileRetrieve(SKLOG_T_Ctx *t_ctx,
	SKLOG_CONNECTION *c)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    unsigned char *tlv = 0;
    unsigned char *value = 0;
    unsigned int len = 0;

    unsigned char wbuf[SKLOG_BUFFER_LEN] = { 0 };
    unsigned int wlen = 0;
    
    if ( t_ctx == NULL ) {
		ERROR("argument 1 must be not NULL");
		return SKLOG_FAILURE;
	}

    t_ctx->lsdriver->retrieve_logfiles(&value,&len);

    if ( tlv_create_message(LOG_FILES,len,value,&tlv,&wlen) == SKLOG_FAILURE ) {
        ERROR("tlv_create_message() failure");
        return SKLOG_FAILURE;
    }
    memcpy(wbuf,tlv,wlen); free(tlv);

	write2file("t_out_retrieve.dat", "w+", wbuf, wlen);
	
	#ifdef DO_TESTS
	
		write2file("data/retrieve.dat", "w+", wbuf, wlen);
		
	#else
	
    #ifdef USE_BIO
    if ( BIO_write(c->bio,wbuf,wlen) <= 0 ) {
            ERR_print_errors_fp(stderr);
            return SKLOG_FAILURE;
    }
    #endif

    #ifdef USE_SSL
    if ( SSL_write(c->ssl,wbuf,wlen) <= 0 ) {
            ERR_print_errors_fp(stderr);
            return SKLOG_FAILURE;
    }
    #endif
    
    #endif

    return SKLOG_SUCCESS;
}

/*
 * manage logfile verification requests
 * 
 */
 
SKLOG_RETURN SKLOG_T_ManageLogfileVerify(SKLOG_T_Ctx *t_ctx,
	SKLOG_CONNECTION *c, char *logfile_id)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    unsigned char wbuf[SKLOG_BUFFER_LEN] = { 0 };
    unsigned int wlen = 0;

    unsigned char uuid[UUID_STR_LEN+1] = { 0 };

    unsigned char *tlv = 0;
    
    if ( t_ctx == NULL ) {
		ERROR("argument 1 must be not NULL");
		return SKLOG_FAILURE;
	}
	
	if ( logfile_id == NULL ) {
		ERROR("argument 3 must be not NULL");
		return SKLOG_FAILURE;
	}

    memcpy(uuid,logfile_id,UUID_STR_LEN);

    if ( t_ctx->lsdriver->verify_logfile(uuid) == SKLOG_FAILURE ) {
        tlv_create_message(VERIFY_LOGFILE_FAILURE,0,NULL,&tlv,&wlen);
        memcpy(wbuf,tlv,wlen); free(tlv);
    } else {
        tlv_create_message(VERIFY_LOGFILE_SUCCESS,0,NULL,&tlv,&wlen);
        memcpy(wbuf,tlv,wlen); free(tlv);
    }

	write2file("t_out_verify.dat", "w+", wbuf, wlen);
	#ifdef DO_TESTS
		write2file("data/verify_result.dat", "w+", wbuf, wlen);
	#else
	
    #ifdef USE_BIO
    if ( BIO_write(c->bio,wbuf,wlen) <= 0 ) {
            ERR_print_errors_fp(stderr);
            return SKLOG_FAILURE;
    }
    #endif

    #ifdef USE_SSL
    if ( SSL_write(c->ssl,wbuf,wlen) <= 0 ) {
            ERR_print_errors_fp(stderr);
            return SKLOG_FAILURE;
    }
    #endif
    #endif

    return SKLOG_SUCCESS;
}

/*
 * run T server application
 * 
 */
 
int conn_count = 0;

/* SIGCHLD handler */

void sigchld_h(int signum)
{
	pid_t pid = 0;
	int status = 0;
	
	while ( ( pid = waitpid(-1, &status, WNOHANG) ) > 0 ) {
		NOTIFY("child %d terminated with status %d", pid, status);
		conn_count--;
	}
}

/* server HELLO */

typedef enum {
	logging_session_init,
	logfile_upload,
	logfile_retrieve,
	logfile_verification,
	
	none
} action_t;

static action_t t_hello(SSL *ssl, unsigned int *payload_len, 
	unsigned char **payload)
{
	int rlen = 0;
	unsigned char rbuf[SKLOG_BUFFER_LEN+1] = { 0x0 };
	
	uint32_t type = 0;
	unsigned int len = 0;
	unsigned char *value = 0;
	
	action_t action = none;
	
	/* read from network */
	
	rlen = SSL_read(ssl, rbuf, SKLOG_BUFFER_LEN);
	
	if ( rlen < 0 ) {
		ERROR("SSL_read() failure");
		ERR_print_errors_fp(stderr);
		return action;
	}
	
	SHOWBUF("hello_buffer", rbuf, rlen);
	
	/* get TYPE from TLV message */
	
	if ( tlv_get_type(rbuf, &type) == SKLOG_FAILURE ) {
		ERROR("tlv_get_type() failure");
		return action;
	}
	
	switch ( type ) {
		case M0_MSG:
		
			/* get LEN from TLV message */
			
			if ( tlv_get_len(rbuf, &len) == SKLOG_FAILURE ) {
				ERROR("tlv_get_len() failure");
				break;
			}
			
			/* get VALUE from TLV message */
			
			if ( tlv_get_value(rbuf, &value) == SKLOG_FAILURE ) {
				ERROR("tlv_get_value() failure");
				break;
			}
			
			*payload = value;
			*payload_len = len;
			
			action = logging_session_init;

			break;
			
		case LOGFILE_UPLOAD_REQ:
		
			action = logfile_upload;
			break;
			
		case RETR_LOG_FILES:
		
			action = logfile_retrieve;
			break;
			
		case VERIFY_LOGFILE:
			
			/* get LEN from TLV message */
			
			if ( tlv_get_len(rbuf, &len) == SKLOG_FAILURE ) {
				ERROR("tlv_get_len() failure");
				break;
			}
			
			/* get VALUE from TLV message */
			
			if ( tlv_get_value(rbuf, &value) == SKLOG_FAILURE ) {
				ERROR("tlv_get_value() failure");
				break;
			}
			
			*payload = value;
			*payload_len = len;
			
			action = logfile_verification;
			
			break;
			
		default:
			return (action_t)none;
	}
	
	return action;
}
 
SKLOG_RETURN SKLOG_T_RunServer(SKLOG_T_Ctx *t_ctx)
{
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	int maxconn = 0;
	int do_verify = 0;
	
	int rv = 0;
	
	int lsock = 0;
	int csock = 0;
	
	char cli_addr[INET_ADDRSTRLEN+1] = { 0x0 };
	
	pid_t pid = 0;
	
	FILE *fp = 0;
	
	SSL_CTX *ssl_ctx = 0;
	SSL *ssl = 0;
	BIO *sbio = 0;
	
	SKLOG_CONNECTION *conn = 0;
	
	action_t action = (action_t)none;
	
	unsigned char *payload = 0;
	unsigned int payload_len = 0;
	
	unsigned char wbuf[SKLOG_BUFFER_LEN+1] = { 0x0 };
	int wlen = 0;
	
	char logfile_id[UUID_STR_LEN+1] = { 0x0 };
	
	unsigned char *m1 = 0;
	unsigned int m1_len = 0;
	
	/* check input parameters */
	
	if ( t_ctx == NULL ) {
		ERROR("Bad input parameter. Please, double-check it!!!");
		goto input_params_error;
	}
	
	/* initialize SKLOG_CONNECTION */
	
	conn = SKLOG_CONNECTION_New();
	
	if ( conn == NULL ) {
		ERROR("SKLOG_CONNECTION_New() failure");
		goto input_params_error;
	}

	/* init OpenSSL library */
	
	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();
	
	/* init SSL_CTX structure */
	
	rv = ssl_init_SSL_CTX(SSLv3_server_method(),
		t_ctx->t_cert_file_path, t_ctx->t_privkey_file_path, do_verify,
		t_ctx->t_privkey_file_path, &ssl_ctx);
		
	if ( rv == SKLOG_FAILURE || ssl_ctx == NULL ) {
		ERROR("ssl_init_SSL_CTX() failure");
		goto error;
	}
	
	conn->ssl_ctx = ssl_ctx;
	
	/* init SSL structure */
	
	rv = ssl_init_SSL(ssl_ctx, &ssl);
	
	if ( rv == SKLOG_FAILURE || ssl == NULL ) {
		ERROR("ssl_init_SSL() failure");
		goto error;
	}
	
	conn->ssl = ssl;
	
	/* create listen socket */
	
	rv = tcp_socket(&lsock);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("tcp_socket() failure");
		goto error;
	}
	
	conn->lsock = lsock;
	
	/* bind listen socket */
	
	rv = tcp_bind(lsock, t_ctx->t_address, t_ctx->t_port);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("tcp_bind() failure");
		goto error;
	}
	
	/* listen */
	
	rv = tcp_listen(lsock);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("tcp_listen() failure");
		goto error;
	}
	
	signal(SIGCHLD, sigchld_h);
	
	while ( 1 ) {
		
		rv = tcp_accept(lsock, &csock, cli_addr);
		
		if ( rv == SKLOG_FAILURE ) {
			ERROR("tcp_accept() failure");
			goto error;
		}
		
		conn->csock = csock;
		
		/* check for available connection */
		
		if ( maxconn > 0 ) {
			if ( conn_count >= maxconn ) {
				NOTIFY("No more connection available");
				close(csock);
				continue;
			}
		}
		
		pid = fork();
		
		if ( pid == 0 ) {
			/* I'm a child process */
			
			close(lsock);
			
			/* setup socket BIO */
			
			sbio = BIO_new_socket(csock, BIO_NOCLOSE);
			SSL_set_bio(ssl, sbio, sbio);
			
			/* SSL handshake */
			
			rv = SSL_accept(ssl);
			
			if ( rv <= 0 ) {
				ERROR("SSL_accept() failure");
				ERR_print_errors_fp(stderr);
				goto child_error;
			}
			
			/* server hello */
			
			action = t_hello(ssl, &payload_len, &payload);
			
			/* action */
			
			switch( action ) {
				case logging_session_init:
					
					/*
					 * m0 = payload
					 * m0_len = payload_len
					 * 
					 */
					 
					rv = SKLOG_T_ManageLoggingSessionInit(t_ctx, payload,
						payload_len, cli_addr, &m1, &m1_len);
						
					if ( rv == SKLOG_FAILURE ) {
						ERROR("SKLOG_T_ManageLoggingSessionInit() failure");
						goto child_error;
					}
					
					memcpy(wbuf, m1, m1_len);
					wlen = m1_len;
					free(m1);
					
					rv = send_m1(t_ctx, conn, wbuf, wlen);
					
					if ( rv == SKLOG_FAILURE ) {
						ERROR("send_m1() failure");
						goto child_error;
					} 
					
					break;
					
				case logfile_retrieve:
				
					rv = SKLOG_T_ManageLogfileRetrieve(t_ctx, conn);
					
					if ( rv == SKLOG_FAILURE ) {
						ERROR("SKLOG_T_ManageLogfileRetrieve() failure");
						goto child_error;
					}
					
					break;
					
				case logfile_upload:
				
					rv = SKLOG_T_ManageLogfileUpload(t_ctx, conn);
					
					if ( rv == SKLOG_FAILURE ) {
						ERROR("SKLOG_T_ManageLogfileUpload() failure");
						goto child_error;
					}
					
					break;
					
				case logfile_verification:
				
					/*
					 * logfile_id = payload
					 * 
					 */
					
					memcpy(logfile_id, payload, UUID_STR_LEN);
					
					rv = SKLOG_T_ManageLogfileVerify(t_ctx, conn, logfile_id);
					
					if ( rv == SKLOG_FAILURE ) {
						ERROR("SKLOG_T_ManageLogfileUpload() failure");
						goto child_error;
					}
					 
					break;
					
				case none:
				default:
					break;
			}
			
			/* child termination */
			
child_error:
			/* free SSL and SSL_CTX structures */
			
			rv = SSL_shutdown(ssl);
			
			if ( rv < 0 ) {
				ERROR("SSL_shutdown() failure")
				ERR_print_errors_fp(stderr);
				exit(1);
			}
			
			SSL_free(ssl);
			SSL_CTX_free(ssl_ctx);
			
			/* free OpenSSL error strings */
			
			ERR_free_strings();
			
			/* close socket */
			
			close(csock);
			
			exit(0);
			
		} else if ( pid > 0 ) {
			/* I'm a parent process */
			
			/* increment connection counter */
			
			conn_count++;
			
			/* close connection socket */
			
			close(csock);
			
			NOTIFY("child %d spawned", pid);
			
			if ( maxconn > 0 ) 
				NOTIFY("%d connections still available",
					maxconn-conn_count);
				
		} else {
			/* Dho!!! */
error:
			if ( lsock > 0 )
				close(lsock);
				
			if ( csock > 0 )
				close(csock);
				
			if ( fp > 0 )
				fclose(fp);
			
			if ( ssl > 0)
				SSL_free(ssl);
				
			if ( ssl_ctx > 0 )
				SSL_CTX_free(ssl_ctx);
				
			ERR_free_strings();
		
			exit (1);				
		} 
	} 
	
input_params_error:
	exit(1);
}





