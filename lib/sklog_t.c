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
 
void sigchld_h (int signum)
{
    pid_t pid;
    int status;
    char msg[SKLOG_SMALL_BUFFER_LEN] = { 0 };
    while ( (pid = waitpid(-1,&status,WNOHANG)) > 0)
    
    sprintf(msg,"child %d terminated with status %d",pid,status);
    NOTIFY(msg);
}

SKLOG_RETURN SKLOG_T_RunServer(SKLOG_T_Ctx *t_ctx)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    SKLOG_CONNECTION *c = 0;
    int enable_verify = 0;

    unsigned char rbuf[SKLOG_BUFFER_LEN] = { 0 };
    int  rlen = 0;
    unsigned char wbuf[SKLOG_BUFFER_LEN] = { 0 };
    int  wlen = 0;

    int ret = 0;

    struct sockaddr_in    sa_cli;
    socklen_t             client_len = 0;

    pid_t pid = 0;

    char logfile_uuid[UUID_STR_LEN+1] = { 0 };

    uint32_t msg_type = 0;
    unsigned int len = 0;
    unsigned char *value = 0;

    unsigned char *m0 = 0;
    unsigned int  m0_len = 0;

    unsigned char *m1 = 0;
    unsigned int  m1_len = 0;

    char u_address[INET_ADDRSTRLEN] = { 0 };
    
    if ( t_ctx == NULL ) {
		ERROR("argument 1 must be not NULL");
		return SKLOG_FAILURE;
	}

    c = new_connection();

    //----------------------------------------------------------------//
    //             initialize SSL_CTX and SSL structures              //
    //----------------------------------------------------------------//
    
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();

    //~ create SSL_CTX structure
    c->ssl_ctx = SSL_CTX_new(SSLv3_method());

    //~ load server certificate
    ret = SSL_CTX_use_certificate(c->ssl_ctx,t_ctx->t_cert);

    if ( ret <= 0 ) {
        ERR_print_errors_fp(stderr);
        return SKLOG_FAILURE;
    }

    //~ load server private key
    ret = SSL_CTX_use_PrivateKey(c->ssl_ctx,t_ctx->t_privkey);

    if ( ret <= 0 ) {
        ERR_print_errors_fp(stderr);
        return SKLOG_FAILURE;
    }

    //~ check private key
    if ( SSL_CTX_check_private_key(c->ssl_ctx) <= 0 ) {
        ERR_print_errors_fp(stderr);
        return SKLOG_FAILURE;
    }

    if ( enable_verify ) {

        //~ load CA certificate
        ret = SSL_CTX_load_verify_locations(c->ssl_ctx,
                                            t_ctx->t_cert_file_path,
                                            NULL);
    
        if ( ret <= 0 ) {
            ERR_print_errors_fp(stderr);
            return SKLOG_FAILURE;
        }

        //~ set verification parameters
        SSL_CTX_set_verify(c->ssl_ctx, SSL_VERIFY_PEER,NULL);
        SSL_CTX_set_verify_depth(c->ssl_ctx, 1);
    }

    c->ssl = SSL_new(c->ssl_ctx);

    //~ create and bind lsock
    c->lsock = tcp_bind(t_ctx->t_address,t_ctx->t_port);

    if ( c->lsock < 0 ) {
        ERROR("tcp_bind() failure")
        return SKLOG_FAILURE;
    }
    
    //~ listen on the listen socket 
    if ( listen(c->lsock,5) < 0 ) {
        ERROR("listen() failure");
        return SKLOG_FAILURE;
    }

    //----------------------------------------------------------------//
    //                          SERVER WORK                           //
    //----------------------------------------------------------------//

    signal(SIGCHLD,sigchld_h);
    
    while ( 1 ) {
    
        //~ create csock
        c->csock = accept(c->lsock,(struct sockaddr*)&sa_cli,&client_len);

        pid = fork();

        if ( pid < 0 ) {
        //------------------------------------------------------------//
        //                        fork() error                        //
        //------------------------------------------------------------//
            
            ERROR("fork() fails")
            return SKLOG_FAILURE;
            
        } else if ( pid == 0 ) {
        //------------------------------------------------------------//
        //                       children process                     //
        //------------------------------------------------------------//
			
			//~ getchar();
			
            //~ close lsock
            close(c->lsock);
            
            //~ setup BIO structure

            c->bio = BIO_new(BIO_s_socket());
            BIO_set_fd(c->bio,c->csock,BIO_NOCLOSE);
            SSL_set_bio(c->ssl,c->bio,c->bio);
            
            
            /*
            c->sock_bio = BIO_new(BIO_s_socket());
            BIO_set_fd(c->sock_bio, c->csock, BIO_NOCLOSE);
            SSL_set_bio(c->ssl, c->sock_bio, c->sock_bio);
            */
        
            //~ SSL handshake (server side)
            ret = SSL_accept(c->ssl);
            
            if ( ret <= 0 ) {
				ERR_print_errors_fp(stderr);
				//~ goto child_error;
			}

			/*
            //~ setup I/O bio
            
            if ( ( c->bio = BIO_new(BIO_f_buffer()) ) == NULL ) {
				ERR_print_errors_fp(stderr);
				//~ goto child_error;
			} 
			
			if ( ( c->ssl_bio = BIO_new(BIO_f_ssl())) == NULL ) {
				ERR_print_errors_fp(stderr);
				//~ goto child_error;
			}
			
			BIO_set_ssl(c->ssl_bio, c->ssl, BIO_CLOSE);
			BIO_push(c->bio, c->ssl_bio);
			*/
    
            //~ read from bio
            if ( (rlen = BIO_read(c->bio,rbuf,SKLOG_BUFFER_LEN-1)) <= 0 ) {
                ERR_print_errors_fp(stderr);
                exit(1);
            }
            
            //~ parse received data
            if ( tlv_get_type(rbuf,&msg_type) == SKLOG_FAILURE ) {
                ERROR("tlv_get_type() failure")
                goto failure;
            }

            switch ( msg_type ) {
                
                case M0_MSG:
                //----------------------------------------------------//
                //              initialize logging session            //
                //----------------------------------------------------//
                    #ifdef DO_TRACE
                    NOTIFY("received M0_MSG message");
                    #endif

                    tlv_get_len(rbuf,&m0_len);
                    tlv_get_value(rbuf,&m0);

                    inet_ntop(AF_INET,&(sa_cli.sin_addr),u_address,INET_ADDRSTRLEN);

                    ret = SKLOG_T_ManageLoggingSessionInit(t_ctx,
                        m0,m0_len,u_address,&m1,&m1_len);

                    if ( ret == SKLOG_FAILURE ) {
                        ERROR("SKLOG_T_ManageLoggingSessionInit() failure");
                        goto failure;
                    }

                    memcpy(wbuf,m1,m1_len);
                    wlen = m1_len; free(m1);

                    if ( (ret = send_m1(t_ctx,c,wbuf,wlen) ) == SKLOG_FAILURE ) {
                        ERROR("send_m1() failure");
                        goto failure;
                    }
                    
                    break;
                    
                case LOGFILE_UPLOAD_REQ:
                //----------------------------------------------------//
                //                logfile upload request              //
                //----------------------------------------------------//
                    #ifdef DO_TRACE
                    NOTIFY("received LOGFILE_UPLOAD_REQ message");
                    #endif
                    
                    ret = SKLOG_T_ManageLogfileUpload(t_ctx,c);
                    
                    if ( ret == SKLOG_FAILURE ) {
                        ERROR("SKLOG_T_ManageLogfileUpload() failure");
                        goto failure;
                    }
                    
                    break;
                case RETR_LOG_FILES:
                //----------------------------------------------------//
                //             retrieve logfile list request          //
                //----------------------------------------------------//
                    #ifdef DO_TRACE
                    NOTIFY("received RETR_LOG_FILES message");
                    #endif

                    ret = SKLOG_T_ManageLogfileRetrieve(t_ctx,c);

                    if ( ret == SKLOG_FAILURE ) {
                        ERROR("SKLOG_T_ManageLogfileRetrieve() failure");
                        goto failure;
                    }

                    break;

                case VERIFY_LOGFILE:
                //----------------------------------------------------//
                //              logfile verification request          //
                //----------------------------------------------------//
                    #ifdef DO_TRACE
                    NOTIFY("received VERIFY_LOGFILE message");
                    #endif
                    
                    tlv_get_len(rbuf,&len);
                    tlv_get_value(rbuf,&value);

                    memcpy(logfile_uuid,value,UUID_STR_LEN);
                    
                    
                    SKLOG_T_ManageLogfileVerify(t_ctx,c,logfile_uuid);
                    break;
                default:
                    NOTIFY("protocol error");
                    break;
            }
failure:
            destroy_ssl_connection(c);
            free_conenction(c);
            exit(0);
            
        } else {
        //------------------------------------------------------------//
        //                     parent process                         //
        //------------------------------------------------------------//

            NOTIFY("Server says: goodbye...");
            fprintf(stderr, ">>> %d <<<\n", pid);
            close(c->csock);

        }
    }

    destroy_ssl_connection(c);
    free_conenction(c);
    return SKLOG_SUCCESS;
}
