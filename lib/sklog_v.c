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

#include <openssl/err.h>
#include <openssl/pem.h>
//~ #include <openssl/rand.h>
//~ #include <openssl/hmac.h>

#include <openssl/evp.h>
#include <openssl/ssl.h>

/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/

static SKLOG_RETURN
conn_open(SKLOG_V_Ctx         *v_ctx,
          SKLOG_CONNECTION    *conn)
{
    SSL_load_error_strings();

    conn->ssl_ctx = init_ssl_ctx_c(v_ctx->v_cert,v_ctx->v_privkey,
                                   v_ctx->t_cert_path,1);

    if ( conn->ssl_ctx == NULL ) {
        ERROR("init_ssl_ctx() failure")
        return SKLOG_FAILURE;
    }

    conn->socket = tcp_connect(v_ctx->t_address,v_ctx->t_port);

    if ( conn->socket < 0 ) {
        ERROR("tcp_connect() failure")
        return SKLOG_FAILURE;
    }

    conn->ssl = init_ssl_structure_c(conn->ssl_ctx,conn->socket);

    if ( conn->ssl == NULL ) {
        ERROR("init_ssl_structure() failure")
        return SKLOG_FAILURE;
    }

    return SKLOG_SUCCESS;
}

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

    char *v_cert = SKLOG_DEF_V_CERT_PATH;

    FILE *fp = 0;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    //~ load certificate
    ctx->v_cert = X509_new();

    fp = fopen(v_cert,"r");
    if ( fp != NULL ) {
        if ( !PEM_read_X509(fp,&ctx->v_cert,NULL,NULL) ) {
            ERR_print_errors_fp(stderr);
            goto error;
        }
        fclose(fp);
    } else {
        ERROR("unable to read V's X509 file")
        goto error;
    }

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

    TO_IMPLEMENT;

    return SKLOG_TO_IMPLEMENT;
}

SKLOG_RETURN
SKLOG_V_RetrieveLogFiles(SKLOG_V_Ctx *v_ctx)
{
    #ifdef DO_TRACE
    DEBUG
    #endif
    
    SKLOG_CONNECTION conn = {0,0,0};
    
    int nread = 0;
    int nwrite = 0;
    unsigned char buffer[SKLOG_BUFFER_LEN] = { 0 };

    unsigned int len = 0;
    char value[SKLOG_BUFFER_LEN] = { 0 };

    char *uuid = 0;
    unsigned int index = 1;

    SSL_load_error_strings();

    //~ create and send RETR_LOG_FILES message
    if ( tlv_create(RETR_LOG_FILES,0,0,buffer) == SKLOG_FAILURE ) {
        ERROR("tlv_create() failure")
        goto error;
    }

    //~ open connection (to check)
    if ( conn_open(v_ctx,&conn) == SKLOG_FAILURE ) {
        ERROR("conn_open() failure")
        goto error;
    }

    nwrite = SSL_write(conn.ssl,buffer,8);
    memset(buffer,0,SKLOG_BUFFER_LEN);

    if ( nwrite < 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }
    
    //~ waiting for response
    nread = SSL_read(conn.ssl,buffer,SKLOG_BUFFER_LEN-1);

    if ( nread < 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    //~ close connection (to check)
    if ( conn_close(&conn) == SKLOG_FAILURE ) {
        ERROR("conn_close() failure")
        goto error;
    }

    if ( tlv_parse(buffer,LOG_FILES,value,&len) == SKLOG_FAILURE ) {
        ERROR("Message is bad structured: expected LOG_FILES");
        goto error;
    }

    memset(buffer,0,SKLOG_BUFFER_LEN);
    
    
    //~ parse and print values
    
    fprintf(stdout,"List of verifiable log files:\n=====================================================================\n");

    uuid = strtok(value,";");
    fprintf(stdout,"%3d) %s\n",index++,uuid);

    while ( (uuid = strtok(NULL,";")) != NULL ) {
        fprintf(stdout,"%3d) %s\n",index++,uuid);
    }

    ERR_free_strings();
    return SKLOG_SUCCESS;

error:
    ERR_free_strings();
    return SKLOG_FAILURE;
}
