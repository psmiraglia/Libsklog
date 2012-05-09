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
#include "sklog_u.h"

SKLOG_U_Ctx*
SKLOG_U_NewCtx(void)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    SKLOG_U_Ctx *ctx = calloc(1,sizeof(SKLOG_U_Ctx));

    if ( ctx == NULL ) {
        ERROR("calloc() failure");
        return NULL;
    }

    /*
    ctx->lsdriver = calloc(1,sizeof(SKLOG_U_STORAGE_DRIVER));

    if ( ctx->lsdriver == NULL ) {
        ERROR("calloc() failure");
        return NULL;
    }
    
    #ifdef USE_FILE
    ctx->lsdriver->store_logentry =    &sklog_file_u_store_logentry;
    ctx->lsdriver->flush_logfile =     &sklog_file_u_flush_logfile;
    ctx->lsdriver->init_logfile =      &sklog_file_u_init_logfile;
    #elif USE_SYSLOG
    ctx->lsdriver->store_logentry =    &sklog_syslog_u_store_logentry;
    ctx->lsdriver->flush_logfile =     &sklog_syslog_u_flush_logfile;
    ctx->lsdriver->init_logfile =      &sklog_syslog_u_init_logfile;
    #elif USE_SQLITE
    ctx->lsdriver->store_logentry =    &sklog_sqlite_u_store_logentry;
    ctx->lsdriver->flush_logfile =     &sklog_sqlite_u_flush_logfile;
    ctx->lsdriver->init_logfile =      &sklog_sqlite_u_init_logfile;
    #else
    //~ todo: manage default case
    #endif
    */

    return ctx;
}

SKLOG_RETURN
SKLOG_U_FreeCtx(SKLOG_U_Ctx **ctx)
{
    #ifdef DO_TRACE
    DEBUG
    #endif
    
    if ( *ctx == NULL ) {
		ERROR("argument 1 must be not NULL");
		return SKLOG_FAILURE;
	}
    
    X509_free((*ctx)->u_cert);
    X509_free((*ctx)->t_cert);
    EVP_PKEY_free((*ctx)->u_privkey);

    memset(*ctx,0,sizeof(SKLOG_U_Ctx));
    *ctx = 0;
    
    return SKLOG_SUCCESS;
}

SKLOG_RETURN
SKLOG_U_LogEvent(SKLOG_U_Ctx        *u_ctx,
                 SKLOG_DATA_TYPE    type,
                 char               *data,
                 unsigned int       data_len,
                 char               **le,
                 unsigned int       *le_len)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    unsigned char *data_blob = 0;
    unsigned int data_blob_len = 0;

    if ( SKLOG_alloc(&data_blob,unsigned char,data_len) == SKLOG_FAILURE ) {
        ERROR("SKLOG_alloc() failure");
        goto error;
    }
    memcpy(data_blob,data,data_len);

    //~ check the state of the logging session
    if ( u_ctx->context_state == SKLOG_U_CTX_NOT_INITIALIZED ) {
        if ( initialize_context(u_ctx) == SKLOG_FAILURE ) {
            ERROR("context initialization process fails")
            goto error;
        }
        if ( initialize_logging_session(u_ctx,0,0,0,0,0) == SKLOG_FAILURE ) {
            ERROR("loggin session initialization process fails")
            goto error;
        }
    }
    
    //~ write logentry
    if ( create_logentry(u_ctx,type,data_blob,
                         data_len,1,le,le_len) == SKLOG_FAILURE ) {
        ERROR("create_logentry() failure")
        goto error;
    }

    if ( u_ctx->logging_session_mgmt != SKLOG_MANUAL ) {
        //~ check if the logging session needs to be renewed
        if ( u_ctx->logfile_counter == u_ctx->logfile_size -1 ) {
    
            WARNING("The logging session has to be renewed!!!")
    
            SKLOG_DATA_TYPE type = NormalCloseMessage;
            struct timeval now;
    
            gettimeofday(&now,NULL);
        
            if ( serialize_timeval(&now,&data_blob,
                                   &data_blob_len) == SKLOG_FAILURE ) {
                ERROR("serialize_timeval() failure")
                goto error;
            }
    
            if ( create_logentry(u_ctx,type,data_blob,
                                 data_blob_len,0,0,0) == SKLOG_FAILURE ) {
                ERROR("create_logentry() failure")
                goto error;
            }
    
            //~ send all generated log-entries to T
            if ( flush_logfile_execute(u_ctx,&now) == SKLOG_FAILURE ) {
                ERROR("flush_logfile_execute() failure")
                goto error;
            }
    
            //~ flush the current context and mark it as uninitialized
            memset(u_ctx,0,sizeof(*u_ctx));
            u_ctx->context_state = SKLOG_U_CTX_NOT_INITIALIZED;
        }
    }

    free(data_blob);
    return SKLOG_SUCCESS;

error:
    if ( data_blob > 0 ) free(data_blob);
    return SKLOG_FAILURE;
}

SKLOG_RETURN
SKLOG_U_Open(SKLOG_U_Ctx     *u_ctx,
             char            **le1,
             unsigned int    *le1_len,
             char            **le2,
             unsigned int    *le2_len)
{
    #ifdef DO_TRACE
    DEBUG
    #endif
    
    if ( u_ctx == NULL ) {
		ERROR("argument 1 must be not NULL");
		goto error;
	}
	
    if ( initialize_context(u_ctx) == SKLOG_FAILURE ) {
        ERROR("context initialization process fails")
        goto error;
    }

    u_ctx->logging_session_mgmt = SKLOG_MANUAL;
    
    if ( initialize_logging_session(u_ctx,1,le1,le1_len,le2,le2_len) == SKLOG_FAILURE ) {
        ERROR("loggin session initialization process fails")
        goto error;
    }

    return SKLOG_SUCCESS;
error:
    return SKLOG_FAILURE;
}

SKLOG_RETURN
SKLOG_U_Close(SKLOG_U_Ctx     *u_ctx,
              char            **le,
              unsigned int    *le_len)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    SKLOG_DATA_TYPE type = NormalCloseMessage;
    struct timeval now;

    unsigned char *data_blob = 0;
    unsigned int data_blob_len = 0;

    gettimeofday(&now,NULL);

    if ( serialize_timeval(&now,&data_blob,
                           &data_blob_len) == SKLOG_FAILURE ) {
        ERROR("serialize_timeval() failure")
        goto error;
    }

    if ( create_logentry(u_ctx,type,data_blob,
                         data_blob_len,1,le,le_len) == SKLOG_FAILURE ) {
        ERROR("create_logentry() failure")
        goto error;
    }

    //~ send all generated log-entries to T
    if ( flush_logfile_execute(u_ctx,&now) == SKLOG_FAILURE ) {
        ERROR("flush_logfile_execute() failure")
        goto error;
    }

    //~ flush the current context and mark it as uninitialized
    memset(u_ctx,0,sizeof(*u_ctx));
    u_ctx->context_state = SKLOG_U_CTX_NOT_INITIALIZED;

    free(data_blob);
    return SKLOG_SUCCESS;

error:
    if ( data_blob > 0 ) free(data_blob);
    return SKLOG_FAILURE;
}
