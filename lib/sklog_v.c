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
#include "sklog_v.h"

#include <string.h>

#include <netinet/in.h>

#include <openssl/err.h>
#include <openssl/pem.h>
//~ #include <openssl/rand.h>
//~ #include <openssl/hmac.h>

#include <openssl/evp.h>
#include <openssl/ssl.h>

/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/

//~ static SKLOG_RETURN
//~ conn_open(SKLOG_V_Ctx         *v_ctx,
          //~ SKLOG_CONNECTION    *conn)
//~ {
    //~ SSL_load_error_strings();
//~ 
    //~ conn->ssl_ctx = init_ssl_ctx_c(v_ctx->v_cert,v_ctx->v_privkey,
                                   //~ v_ctx->t_cert_path,1);
//~ 
    //~ if ( conn->ssl_ctx == NULL ) {
        //~ ERROR("init_ssl_ctx() failure")
        //~ return SKLOG_FAILURE;
    //~ }
//~ 
    //~ conn->socket = tcp_connect(v_ctx->t_address,v_ctx->t_port);
//~ 
    //~ if ( conn->socket < 0 ) {
        //~ ERROR("tcp_connect() failure")
        //~ return SKLOG_FAILURE;
    //~ }
//~ 
    //~ conn->ssl = init_ssl_structure_c(conn->ssl_ctx,conn->socket);
//~ 
    //~ if ( conn->ssl == NULL ) {
        //~ ERROR("init_ssl_structure() failure")
        //~ return SKLOG_FAILURE;
    //~ }
//~ 
    //~ return SKLOG_SUCCESS;
//~ }

/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/

SKLOG_V_Ctx*
SKLOG_V_NewCtx(void)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    SKLOG_V_Ctx *tmp = 0;

    tmp = calloc(1,sizeof(SKLOG_V_Ctx));

    if ( tmp == NULL ) {
        ERROR("calloc() failure");
        return NULL;
    }

    memset(tmp,0,sizeof(SKLOG_V_Ctx));

    return tmp;
}

SKLOG_RETURN
SKLOG_V_InitCtx(SKLOG_V_Ctx *ctx)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    char *v_cert_path = SKLOG_DEF_V_CERT_PATH;
    char *v_privkey_path = SKLOG_DEF_V_RSA_KEY_PATH;

    FILE *fp = 0;

    int i = 0;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    //~ load certificate
    ctx->v_cert = X509_new();
    fp = fopen(v_cert_path,"r");
    if ( fp != NULL ) {
        if ( !PEM_read_X509(fp,&ctx->v_cert,NULL,RSA_DEFAULT_PASSPHRASE) ) {
            ERR_print_errors_fp(stderr);
            goto error;
        }
        fclose(fp);
    } else {
        ERROR("unable to read V's X509 file")
        goto error;
    }

    //~ load private key
    ctx->v_privkey = EVP_PKEY_new();
    fp = fopen(v_privkey_path,"r");
    if ( fp != NULL ) {
        if ( !PEM_read_PrivateKey(fp,&ctx->v_privkey,NULL,RSA_DEFAULT_PASSPHRASE) ) {
            ERR_print_errors_fp(stderr);
            goto error;
        }
        fclose(fp);
    } else {
        ERROR("unable to read V's private key file")
        goto error;
    }

    //~ set t_address and t_port
    memcpy(ctx->t_address,SKLOG_DEF_T_ADDRESS,strlen(SKLOG_DEF_T_ADDRESS));
    ctx->t_port = SKLOG_DEF_T_PORT;
    memcpy(ctx->t_cert_file_path,SKLOG_DEF_T_CERT_PATH,strlen(SKLOG_DEF_T_CERT_PATH));

    //~
    for ( i = 0 ; i < 256 ; i++ )
        memset(ctx->verifiable_logfiles[i],0,UUID_STR_LEN+1);

    ERR_free_strings();
    return SKLOG_SUCCESS;

error:
    ERR_free_strings();
    return SKLOG_FAILURE;
}

SKLOG_RETURN
SKLOG_V_FreeCtx(SKLOG_V_Ctx **ctx)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    X509_free((*ctx)->v_cert);
    EVP_PKEY_free((*ctx)->v_privkey);
    free(*ctx);
    *ctx = 0;

    return SKLOG_SUCCESS;
}

SKLOG_RETURN
SKLOG_V_RetrieveLogFiles(SKLOG_V_Ctx         *v_ctx,
                         SKLOG_CONNECTION    *c)
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

    //~ retval = setup_ssl_connection(c,v_ctx->t_address,v_ctx->t_port,
                                  //~ v_ctx->v_cert,v_ctx->v_privkey,
                                  //~ v_ctx->t_cert_file_path,DO_NOT_VERIFY);
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

                strncpy(v_ctx->verifiable_logfiles[index++],token,UUID_STR_LEN);
                token = strtok(NULL,";");
            }
            
            break;
        default:
            NOTIFY("Protocol Error");
            break;
    }

    

    ERR_free_strings();
    return SKLOG_SUCCESS;

error:
    //~ close connection
    //~ destroy_ssl_connection(c);
    //~ free_conenction(c);
    
    ERR_free_strings();
    return SKLOG_FAILURE;
}

SKLOG_RETURN
SKLOG_V_VerifyLogFile(SKLOG_V_Ctx         *v_ctx,
                      SKLOG_CONNECTION    *c,
                      unsigned int        logfile_id)
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

    while ( strlen((v_ctx)->verifiable_logfiles[id]) <= 0 ) {
        ERROR("Invalid logfile_id");
        fprintf(stdout,"Select logfile id: ");
        memset(inbuf,0,INBUF_LEN); gets(inbuf);
        sscanf(inbuf,"%d",&id);
    }
    
    memcpy(value,(v_ctx)->verifiable_logfiles[logfile_id],UUID_STR_LEN);
    len = UUID_STR_LEN;

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

SKLOG_RETURN
SKLOG_V_VerifyLogFile_uuid(SKLOG_V_Ctx         *v_ctx,
                           SKLOG_CONNECTION    *c,
                           char                *logfile_id)
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

































                      
