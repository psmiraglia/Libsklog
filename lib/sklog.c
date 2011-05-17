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
**    the Free Software Foundation, either version 3 of the License, or
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

#include "../config.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

#include <openssl/blowfish.h>
#include <openssl/des.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "sklog.h"

/**
 * SKLOG_InitCtx()
 * 
 */
int
SKLOG_InitCtx(SKCTX *ctx)
{
    #ifdef TRACE
    fprintf(stdout,"SKLOG_InitCtx()\n");
    #endif

    if ( ctx ) {
        memset(ctx->last_hash_chain,0,SK_HASH_CHAIN_LEN);
        memset(ctx->auth_key,0,SK_AUTH_KEY_LEN);

        #ifdef TRACE
        int i = 0;
        fprintf(stdout,"\tauth_key: ");
        for ( i = 0 ; i < SK_AUTH_KEY_LEN ; i++ )
            fprintf(stdout,"%2.2x",ctx->auth_key[i]);
        fprintf(stdout,"\n");

        fprintf(stdout,"\tlast_hash_chain: ");
        for ( i = 0 ; i < SK_HASH_CHAIN_LEN ; i++ )
            fprintf(stdout,"%2.2x",ctx->last_hash_chain[i]);
        fprintf(stdout,"\n");
        #endif

        #ifdef USE_QUOTE
        load_tpm_config(&(ctx->tpmctx));

        #ifdef TRACE
        fprintf(stdout,"\tsrkpwd: %s\n",ctx->tpmctx.srkpwd);
        fprintf(stdout,"\taikpwd: %s\n",ctx->tpmctx.aikpwd);
        fprintf(stdout,"\taikid: %d\n",ctx->tpmctx.aikid);
        fprintf(stdout,"\tpcr_to_extend: %d\n",ctx->tpmctx.pcr_to_extend);
        #endif

        #endif

        return SK_SUCCESS;
    } else {
        fprintf(stderr,"ERR: SKLOG_InitCtx(): pointer to ctx MUST BE not null\n");
        return SK_FAILURE;
    }
}

/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/

/**
 * SKLOG_SetAuthKeyZero()
 * 
 */
int
SKLOG_SetAuthKeyZero(SKCTX *ctx,
                     unsigned char *key)
{
    #ifdef TRACE
    fprintf(stdout,"SKLOG_SetAuthKeyZero()\n");
    #endif

    if ( ctx ) {
        if ( key ) {
            memset(ctx->last_hash_chain,0,SK_HASH_CHAIN_LEN);
            memcpy(ctx->auth_key,key,SK_AUTH_KEY_LEN);

            #ifdef TRACE
            int i = 0;
            fprintf(stdout,"\tauth_key: ");
            for ( i = 0 ; i < SK_AUTH_KEY_LEN ; i++ )
                fprintf(stdout,"%2.2x",ctx->auth_key[i]);
            fprintf(stdout,"\n");

            fprintf(stdout,"\tlast_hash_chain: ");
            for ( i = 0 ; i < SK_HASH_CHAIN_LEN ; i++ )
                fprintf(stdout,"%2.2x",ctx->last_hash_chain[i]);
            fprintf(stdout,"\n");
            #endif

            return SK_SUCCESS;
        } else {
            fprintf(stderr,"ERR: SKLOG_SetAuthKeyZero(): pointer to key MUST BE not null\n");
            return SK_FAILURE;
        }
    } else {
        fprintf(stderr,"ERR: SKLOG_SetAuthKeyZero(): pointer to ctx MUST BE not null\n");
        return SK_FAILURE;
    }
}

/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/

/**
 * SKLOG_InitLogEntry()
 * 
 */
int
SKLOG_InitLogEntry(SKLogEntry *skle)
{
    #ifdef TRACE
    fprintf(stdout,"SKLOG_InitLogEntry()\n");
    #endif

    if ( !skle )
        return SK_FAILURE;

    memset(skle->type,0,SK_LOGENTRY_TYPE_LEN);
    skle->data_enc = 0;
    skle->data_enc_len = 0;
    memset(skle->hash,0,SK_HASH_CHAIN_LEN);
    memset(skle->hmac,0,SK_HMAC_LEN);

    #ifdef USE_QUOTE
    skle->quote = 0;
    skle->quote_size = 0;
    #endif

    return SK_SUCCESS;
}

/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/

/**
 * SKLOG_ResetLogEntry()
 * 
 */
int
SKLOG_ResetLogEntry(SKLogEntry *skle)
{
    #ifdef TRACE
    fprintf(stdout,"SKLOG_ResetLogEntry()\n");
    #endif

    if ( !skle )
        return SK_FAILURE;

    memset(skle->type,0,SK_LOGENTRY_TYPE_LEN);
    free(skle->data_enc);
    skle->data_enc_len = 0;
    memset(skle->hash,0,SK_HASH_CHAIN_LEN);
    memset(skle->hmac,0,SK_HMAC_LEN);

    #ifdef USE_QUOTE
    if ( skle->quote )
        free(skle->quote);
    skle->quote_size = 0;
    #endif

    return SK_SUCCESS;
}

/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/

/**
 * SKLOG_LogEntryToBlob()
 * 
 */
int
SKLOG_LogEntryToBlob(unsigned char **blob,
                     unsigned int *blob_len,
                     SKLogEntry *le)
{
    #ifdef TRACE
    fprintf(stdout,"SKLOG_LogEntryToBlob()\n");
    #endif

    int pos = 0;

    *blob_len = SK_LOGENTRY_TYPE_LEN +
                le->data_enc_len +
                SK_HASH_CHAIN_LEN +
                #ifdef USE_QUOTE
                le->quote_size +
                #endif
                SK_HMAC_LEN;

    *blob = calloc(*blob_len,sizeof(char));

    if ( !blob ) {
        fprintf(stderr,"ERR: SKLOG_LogEntryToBlob(): calloc() failure!\n");
        return SK_FAILURE;
    }

    memcpy(*blob+pos,le->type,SK_LOGENTRY_TYPE_LEN);
    pos += SK_LOGENTRY_TYPE_LEN;
    memcpy(*blob+pos,le->data_enc,le->data_enc_len);
    pos += le->data_enc_len;
    memcpy(*blob+pos,le->hash,SK_HASH_CHAIN_LEN);
    pos += SK_HASH_CHAIN_LEN;
    memcpy(*blob+pos,le->hmac,SK_HMAC_LEN);
    pos += SK_HMAC_LEN;

    #ifdef USE_QUOTE
    memcpy(*blob+pos,le->quote,le->quote_size);
    pos += le->quote_size;
    #endif

    if ( pos == *blob_len )
        return SK_SUCCESS;
    else {
        fprintf(stderr,"ERR: SKLOG_LogEntryToBlob(): blob generation failure!\n");
        free(*blob);
        *blob_len = 0;
        return SK_FAILURE;
    }
}

/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/

/**
 * SKLOG_Open()
 * Generate a log entry that represents the log file initialization
 * event.
 *
 */
//~ int
//~ SKLOG_Open(SKCTX *ctx,
           //~ SKLogEntry *skle)
//~ {
    //~ #ifdef TRACE
    //~ fprintf(stdout,"SKLOG_Open()\n");
    //~ #endif
//~ 
    //~ unsigned char enc_key[SK_ENC_KEY_LEN] = {0};
    //~ unsigned char *data_enc = 0;
    //~ unsigned int data_enc_size = 0;
    //~ unsigned char hash_chain[SK_HASH_CHAIN_LEN] = {0};
    //~ unsigned char hmac[SK_HMAC_LEN] = {0};
//~ 
    //~ SKLOG_DATA_TYPE type = LogfileInitialization;
    //~ const char data[] = {"LogfileInitialization"};
    //~ unsigned int data_size = strlen("LogfileInitialization");
//~ 
    //~ /* generate encryption key K using data type and auth_key */
    //~ gen_enc_key(ctx,enc_key,type);
//~ 
    //~ /* encrypt data with generated key K -- done */
    //~ enc_data_aes256(&data_enc,&data_enc_size,(unsigned char *)data,data_size,enc_key);
//~ 
    //~ /* generate hash-chain element  */
    //~ gen_hash_chain(ctx,hash_chain,data_enc,data_enc_size,type);
//~ 
    //~ /* generate digest of hash-chain using the auth_key A */
    //~ gen_hmac(ctx,hmac,hash_chain);
//~ 
    //~ /* re-generate auth_key */
    //~ renew_auth_key(ctx);
//~ 
    //~ /* compose log entry */
    //~ memcpy(skle->type,&type,SK_LOGENTRY_TYPE_LEN);
    //~ skle->data_enc = calloc(data_enc_size,sizeof(char));
    //~ memcpy(skle->data_enc,data_enc,data_enc_size);
    //~ skle->data_enc_len = data_enc_size;
    //~ memcpy(skle->hash,hash_chain,SK_HASH_CHAIN_LEN);
    //~ memcpy(skle->hmac,hmac,SK_HMAC_LEN);
//~ 
    //~ free(data_enc);
//~ 
    //~ return SK_SUCCESS;
//~ }

/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/

/**
 * SKLOG_Close()
 * Generate a log entry that represents the log file closure event.
 *
 */
//~ int
//~ SKLOG_Close(SKCTX *ctx,
            //~ SKLogEntry *skle)
//~ {
    //~ #ifdef TRACE
    //~ fprintf(stdout,"SKLOG_Close()\n");
    //~ #endif
//~ 
    //~ unsigned char enc_key[SK_ENC_KEY_LEN] = {0};
    //~ unsigned char *data_enc = 0;
    //~ unsigned int data_enc_size = 0;
    //~ unsigned char hash_chain[SK_HASH_CHAIN_LEN] = {0};
    //~ unsigned char hmac[SK_HMAC_LEN] = {0};
//~ 
    //~ SKLOG_DATA_TYPE type = LogfileClosure;
    //~ unsigned char data[] = {"LogfileClosure"};
    //~ unsigned int data_size = strlen("LogfileClosure");
//~ 
    //~ /* generate encryption key K using data type and auth_key */
    //~ gen_enc_key(ctx,enc_key,type);
//~ 
    //~ /* encrypt data with generated key K -- done */
    //~ enc_data_aes256(&data_enc,&data_enc_size,(unsigned char *)data,data_size,enc_key);
//~ 
    //~ /* generate hash-chain element  */
    //~ gen_hash_chain(ctx,hash_chain,data_enc,data_enc_size,type);
//~ 
    //~ /* generate digest of hash-chain using the auth_key A */
    //~ gen_hmac(ctx,hmac,hash_chain);
//~ 
    //~ /* re-generate auth_key */
    //~ renew_auth_key(ctx);
//~ 
    //~ /* compose log entry */
    //~ memcpy(skle->type,&type,SK_LOGENTRY_TYPE_LEN);
    //~ skle->data_enc = calloc(data_enc_size,sizeof(char));
    //~ memcpy(skle->data_enc,data_enc,data_enc_size);
    //~ skle->data_enc_len = data_enc_size;
    //~ memcpy(skle->hash,hash_chain,SK_HASH_CHAIN_LEN);
    //~ memcpy(skle->hmac,hmac,SK_HMAC_LEN);
//~ 
    //~ free(data_enc);
//~ 
    //~ return SK_SUCCESS;
//~ }

/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/

/**
 * SKLOG_Write()
 * Generate a log entry that represents the event specified into the
 * data_in buffer.
 *
 */
int
SKLOG_Write(SKCTX *ctx,
            const char *data_in,
            int data_size,
            SKLOG_DATA_TYPE type,
            SKLogEntry *skle)
{
    #ifdef TRACE
    fprintf(stdout,"SKLOG_Write()\n");
    #endif

    unsigned char enc_key[SK_ENC_KEY_LEN] = {0};
    unsigned char *data = 0;
    unsigned char *data_enc = 0;
    unsigned int data_enc_size = 0;
    unsigned char hash_chain[SK_HASH_CHAIN_LEN] = {0};
    unsigned char hmac[SK_HMAC_LEN] = {0};
    #ifdef USE_QUOTE
    unsigned char nonce[NONCE_LEN] = { 0 };
    unsigned char *quote = 0;
    unsigned int quote_size = 0;
    #endif

    if ( !ctx ) {
        /* ctx null */
        return SK_FAILURE;
    }

    if ( !skle ) {
        /* skle null*/
        return SK_FAILURE;
    }

    /* generate encryption key K using data type and auth_key */
    gen_enc_key(ctx,enc_key,type);

    /* encrypt data with generated key K */
    switch ( type ) {
        case LogfileInitialization:
            /**
             * this is a simplified version of LogInitializaion log entry
             */
            data = calloc(BUFFER_LEN,sizeof(char));
            if ( data ) {
                memset(data,0,BUFFER_LEN);
                struct timeval tv;
                gettimeofday(&tv,NULL);
                sprintf((char*)data,"%ld:%ld",tv.tv_sec,tv.tv_usec);
            } else {
                /* calloc() error */
            }
            break;
        case LogfileClosure:
            /**
             * this is a simplified version of LogClosure log entry
             */
            data = calloc(BUFFER_LEN,sizeof(char));
            if ( data ) {
                memset(data,0,BUFFER_LEN);
                struct timeval tv;
                gettimeofday(&tv,NULL);
                sprintf((char*)data,"%ld:%ld",tv.tv_sec,tv.tv_usec);
            } else {
                /* calloc() error */
            }
            break;
        default:
            data = calloc(data_size,sizeof(char));
            if ( data ) {
                memcpy(data,data_in,data_size);
            } else {
                /* calloc() error */
            }
            break;
    }
    enc_data_aes256(&data_enc,&data_enc_size,data,data_size,enc_key);

    /* generate hash-chain element  */
    gen_hash_chain(ctx,hash_chain,data_enc,data_enc_size,type);

    /* generate digest of hash-chain using the auth_key A */
    gen_hmac(ctx,hmac,hash_chain);

    /* re-generate auth_key */
    renew_auth_key(ctx);
    
    #ifdef USE_QUOTE
    /* copute TPM_Quote */
    gen_nonce(nonce,&type,data_enc,data_enc_size,hash_chain,hmac);
    compute_tpm_quote(ctx,nonce,&quote,&quote_size);
    #endif

    /* compose log entry */
    memcpy(skle->type,&type,SK_LOGENTRY_TYPE_LEN);
    skle->data_enc = calloc(data_enc_size,sizeof(char));
    memcpy(skle->data_enc,data_enc,data_enc_size);
    skle->data_enc_len = data_enc_size;
    memcpy(skle->hash,hash_chain,SK_HASH_CHAIN_LEN);
    memcpy(skle->hmac,hmac,SK_HMAC_LEN);
    #ifdef USE_QUOTE
    skle->quote = calloc(quote_size,sizeof(char));
    memcpy(skle->quote,quote,quote_size);
    skle->quote_size = quote_size;
    #endif

    /* free allocated buffers */
    free(data_enc);
    free(data);
    #ifdef USE_QUOTE
    free(quote);
    #endif

    return SK_SUCCESS;
}
