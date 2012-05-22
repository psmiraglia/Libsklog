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

    return ctx;
}

SKLOG_RETURN SKLOG_U_InitCtx(SKLOG_U_Ctx *ctx)
{
	#ifdef DO_TRACE
    DEBUG
    #endif
    
    int rv = SKLOG_SUCCESS;
    
    /* check input parameters */
    
    if ( ctx == NULL ) {
		ERROR("Bad input parameter. Please double-check it!");
		return SKLOG_FAILURE;
	}
	
	/* initialize ctx */
	
	rv = initialize_context(ctx);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("initialize_context() failure");
		return SKLOG_FAILURE;
	}
	
	return SKLOG_SUCCESS;
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

SKLOG_RETURN SKLOG_U_LogEvent(SKLOG_U_Ctx *ctx, SKLOG_DATA_TYPE type,
	char *data, unsigned int data_len, char **logentry,
	unsigned int *logentry_len)
{
	#ifdef DO_TRACE
    DEBUG
    #endif
    
	int rv = SKLOG_SUCCESS;
    
    unsigned char *buf = 0;
    unsigned int bufl = 0;
    
    /* check input parameter */
    
    if ( ctx == NULL || data == NULL ) {
		ERROR("Bad input parameter(s). Please double-check it!");
		return SKLOG_FAILURE;
	}
	
	/* checking for session renewing */
	
	if ( ctx->logfile_counter >= ctx->logfile_size ) {
		WARNING("Logging session needs to be renewed!");
		return SKLOG_SESSION_TO_RENEW;
	}
    
    /* serialize content */
    
    buf = calloc(data_len, sizeof(char));
    
    if ( buf == 0 ) {
		ERROR("calloc() failure");
		goto error;
	}
	
	memcpy(buf, data, data_len);
	bufl = data_len;
	
	/* checking for context initialization */
	
	if ( ctx->context_state != SKLOG_U_CTX_INITIALIZED ) {
		ERROR("Context must be initialized");
		goto error;
	}
	
	/* generate logentry */
	
	rv = create_logentry(ctx, type, buf, bufl, 1, logentry,
		logentry_len);
		
	if ( rv == SKLOG_FAILURE ) {
		ERROR("create_logentry() failure");
		goto error;
	}
	
error:

	if ( buf ) 
		free(buf);
		
	return rv;
}

/**
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
            
            unsigned long now;
    
            if ( time_now_usec(&now) == SKLOG_FAILURE ) {
				ERROR("time_now_usec() failure")
                goto error;
			}
			
            time_serialize(&data_blob, &data_blob_len, now);
    
            if ( create_logentry(u_ctx,type,data_blob,
                                 data_blob_len,0,0,0) == SKLOG_FAILURE ) {
                ERROR("create_logentry() failure")
                goto error;
            }
    
            //~ send all generated log-entries to T
            if ( flush_logfile_execute(u_ctx, now) == SKLOG_FAILURE ) {
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
*/

SKLOG_RETURN
SKLOG_U_Open(SKLOG_U_Ctx *u_ctx, char **le1, unsigned int *le1_len,
	char **le2, unsigned int *le2_len)
{
    #ifdef DO_TRACE
    DEBUG
    #endif
    
    /**
     * NOTES
     * 
     * http://docs.python.org/library/httplib.html
     * 
     */
     
    int rv = SKLOG_SUCCESS;
    
	unsigned char *m0 = 0;
	unsigned int m0_len = 0;
	
	unsigned char *m1 = 0;
	unsigned int m1_len = 0;
	
	char *b64 = 0;
	
	SKLOG_CONNECTION *c = 0;

	/* checking input parameters */
	
	if ( u_ctx == NULL ) {
		ERROR("Argument 1 must be not null");
		goto check_input_error;
	}
	
	/* initialize context */
	
	rv = initialize_context(u_ctx);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("context initialization process fails")
        goto error;
	}
	
	u_ctx->logging_session_mgmt = SKLOG_MANUAL;
	
	/* generate m0 */
	
	rv = generate_m0_message(u_ctx, &m0, &m0_len, le1, le1_len);
		
	if ( rv == SKLOG_FAILURE ) {
		ERROR("generate_m0_message() failure");
		goto error;
	}
	
	/* setup connection */
	
	c = SKLOG_CONNECTION_New();
	
	if ( c == NULL ) {
		ERROR("SKLOG_CONNECTION_New() failure");
		rv = SKLOG_FAILURE;
		goto error;
	}
	
	rv = SKLOG_CONNECTION_Init(c, u_ctx->t_address, u_ctx->t_port,
		u_ctx->u_cert, u_ctx->u_privkey, 0, 0);
		
	if ( rv == SKLOG_FAILURE ) {
		ERROR("SKLOG_CONNECTION_Init() failure");
		goto error;
	}
	
	/* send m0 message */
	
	rv = send_m0(c, m0, m0_len);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("send_m0() failure");
		goto error;
	}
	
	/* waiting for m1 message */
	
	/**
	 * notes
	 * 
	 * timeout verification may be executed by setting
	 * a timeout on SSL_read();
	 * 
	 */
	
	rv = receive_m1(c, &m1, &m1_len);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("receive_m1() failure");
		goto error;
	}
	
	/* free connection */
	
	rv = SKLOG_CONNECTION_Free(&c);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("SKLOG_CONNECTION_Free() failure");
		goto error;
	}
	
	/* check m1 message */
	
	rv = verify_m1_message(u_ctx, m1, m1_len, le2, le2_len);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("verify_m1_message() failure");
		goto error;
	}
	
error:
	
	if ( m0 )
		free(m0);
		
	if ( m1 )
		free(m1);
		
	if ( b64 )
		free(b64);
		
	if ( c )
		SKLOG_CONNECTION_Free(&c);
		
	return rv;
	
check_input_error:
	
	return SKLOG_FAILURE;
}

/*
 * Logging Session Opening: step 1
 * 
 * Client generates the M0 message (stored in buf1) and the first
 * logentry (stored in buf2).
 * 
 */
 
SKLOG_RETURN SKLOG_U_Open_M0(SKLOG_U_Ctx *ctx, unsigned char **buf1,
	unsigned int *buf1l, char **buf2, unsigned int *buf2l)
{
	#ifdef DO_TRACE
    DEBUG
    #endif
    
    /**
     * NOTES
     * 
     * 	- buf1 <-- m0 message
     * 	- buf2 <-- logentry
     *
     */
    
    int rv = SKLOG_SUCCESS;
    
    unsigned char *m0 = 0;
    unsigned int m0_len = 0;
    
    char *logentry = 0;
    unsigned int logentry_len = 0;
    
    /* checking input parameters */
	
	if ( ctx == NULL ) {
		ERROR("Argument 1 must be not null");
		goto check_input_error;
	}
	
	/* checking for context initialization */
	
	if ( ctx->context_state != SKLOG_U_CTX_INITIALIZED ) {
		ERROR("Context must be initialized");
		goto check_input_error;
	}
	
	/* generate m0 and the first logentry */
	
	rv = generate_m0_message(ctx, &m0, &m0_len, &logentry, &logentry_len);
		
	if ( rv == SKLOG_FAILURE ) {
		ERROR("generate_m0_message() failure");
		goto error;
	}
	
	/* save data */
	
	*buf1 = m0;
	*buf1l = m0_len;
	
	*buf2 = logentry;
	*buf2l = logentry_len;
	
error:

	return rv;
	
check_input_error:

	return SKLOG_FAILURE;
}	

/*
 * Logging Session Opening: step 2
 * 
 * Client analyse the M1 message (stored in buf1) received by T and put
 * the verification result in a logentry stored in buf2. 
 * 
 */
 	
SKLOG_RETURN SKLOG_U_Open_M1(SKLOG_U_Ctx *ctx, unsigned char *buf1,
	unsigned int buf1l, char **buf2, unsigned int *buf2l)
{
	#ifdef DO_TRACE
    DEBUG
    #endif
    
    int rv = SKLOG_SUCCESS;
    
    char *logentry = 0;
    unsigned int logentry_len = 0;
    
	/* checking input parameters */
	
	if ( ctx == NULL || buf1 == NULL ) {
		ERROR("Bad input parameter(s). Please double-check it!!!");
		goto check_input_error;
	}
    
    /* check m1 message */
	
	rv = verify_m1_message(ctx, buf1, buf1l, &logentry, &logentry_len);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("verify_m1_message() failure");
		goto error;
	}
	
	/* save data */
	
	*buf2 = logentry;
	*buf2l = logentry_len;
	
error:

	return rv;
	
check_input_error:

	return SKLOG_FAILURE;
}	
	
SKLOG_RETURN
SKLOG_U_Close(SKLOG_U_Ctx *u_ctx, char **le, unsigned int *le_len)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

	int rv = SKLOG_SUCCESS;

    SKLOG_DATA_TYPE type = NormalCloseMessage;
    unsigned long now;

    unsigned char *data_blob = 0;
    unsigned int data_blob_len = 0;
    
    /* check input parameters */
    
    if ( u_ctx == NULL ) {
		ERROR("Bad input parameter(s). Please double-check it!");
		return SKLOG_FAILURE;
	}
	
	/* get current time */

    if ( time_now_usec(&now) == SKLOG_FAILURE ) {
		ERROR("time_now_usec() failure")
        goto error;
	}
	
    time_serialize(&data_blob, &data_blob_len, now);
    
    /* create closure logentry */

	rv = create_logentry(u_ctx, type, data_blob, data_blob_len, 1, le,
		le_len);

    if ( rv == SKLOG_FAILURE ) {
        ERROR("create_logentry() failure")
        goto error;
    }

    /* send all generated log-entries to T */
    
    /**
    if ( flush_logfile_execute(u_ctx, now) == SKLOG_FAILURE ) {
        ERROR("flush_logfile_execute() failure")
        goto error;
    }
    */

    /* flush the current context and mark it as uninitialized */
    
    memset(u_ctx, 0, sizeof(*u_ctx));
    u_ctx->context_state = SKLOG_U_CTX_NOT_INITIALIZED;

    free(data_blob);
    
    return SKLOG_SUCCESS;

error:
    if ( data_blob > 0 ) free(data_blob);
    return SKLOG_FAILURE;
}
