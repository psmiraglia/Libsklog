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

#include "sklog_file.h"

#include <stdio.h>
#include <stdlib.h>

#include <netinet/in.h>

/*--------------------------------------------------------------------*/
/*                             u                                      */
/*--------------------------------------------------------------------*/

SKLOG_RETURN
sklog_file_u_store_logentry(uuid_t             logfile_id,
                            SKLOG_DATA_TYPE    type,
                            unsigned char      *data,
                            unsigned int       data_len,
                            unsigned char      *hash,
                            unsigned char      *hmac)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    //~ todo: store auth_key not in plaintext

    int i = 0;
    int j = 0;

    char f_uuid[UUID_STR_LEN+1] = { 0 };
    char fname[SKLOG_SMALL_BUFFER_LEN] = { 0 };

    //~ compose filename
    uuid_unparse_lower(logfile_id,f_uuid);
    f_uuid[UUID_STR_LEN] = '\0';
    sprintf(fname,"%s/%s.log",SKLOG_U_LOGFILE_PREFIX,f_uuid);

    FILE *fp = fopen(fname,"a+");

    if ( fp == NULL ) {
        ERROR("fopen() failure");
        goto error;
    } 

    char *buf_data = 0;
    buf_data = calloc(1+(data_len*2),sizeof(char)); 
    for ( i = 0 , j = 0 ; i < data_len ; i++ , j += 2)
        sprintf(buf_data+j,"%2.2x",data[i]);
    buf_data[data_len*2] = '\0';

    char buf_hash[1+(SKLOG_HASH_CHAIN_LEN*2)] = { 0 };
    for ( i = 0 , j = 0 ; i < SKLOG_HASH_CHAIN_LEN ; i++ , j += 2)
        sprintf(buf_hash+j,"%2.2x",hash[i]);
    buf_hash[SKLOG_HASH_CHAIN_LEN*2] = '\0';

    char buf_hmac[1+(SKLOG_HMAC_LEN*2)] = { 0 };
    for ( i = 0 , j = 0 ; i < SKLOG_HMAC_LEN ; i++ , j += 2)
        sprintf(buf_hmac+j,"%2.2x",hmac[i]);
    buf_hmac[SKLOG_HMAC_LEN*2] = '\0';

    fprintf(fp,"%d|%s|%s|%s\n",type,buf_data,buf_hash,buf_hmac);

    fclose(fp);

    return SKLOG_SUCCESS;

error:
    return SKLOG_FAILURE; 
}  

SKLOG_RETURN
sklog_file_u_flush_logfile(uuid_t            logfile_id,
                           struct timeval    *now,
                           SSL               *ssl)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    SKLOG_DATA_TYPE w = 0;
    unsigned char *type = 0;
    unsigned int type_len = 0;
    unsigned char *enc_data = 0;
    unsigned int enc_data_len = 0;
    unsigned char *y = 0;
    unsigned int y_len = 0;
    unsigned char *z = 0;
    unsigned int z_len = 0;

    ssize_t nread = 0;
    size_t dummy = 0;
    char *line = 0;
    char *token = 0;
    int tokenl = 0;

    struct tm ts;
    char ts_str[SKLOG_SMALL_BUFFER_LEN] = { 0 };

    char f_uuid[UUID_STR_LEN+1] = { 0 };
    char fname[SKLOG_SMALL_BUFFER_LEN] = { 0 };

    //~ compose filename
    uuid_unparse_lower(logfile_id,f_uuid);
    f_uuid[UUID_STR_LEN] = '\0';
    sprintf(fname,"%s/%s.log",SKLOG_U_LOGFILE_PREFIX,f_uuid);

    FILE *fp = fopen(fname,"r");

    if ( fp == NULL ) {
        ERROR("fopen() failure");
        goto error;
    } 

    //~ flush logfile
    while ( ( nread = getline(&line,&dummy,fp) ) != -1 ) {

        //~ chek
        if ( strstr(line,"LOGFILE_OPEN:") != NULL ||
             strstr(line,"LOGFILE_CLOSE:") != NULL )
             continue;

        //~ get type
        token = strtok(line,"|");
        tokenl = strlen(token);
        w = htonl(atoi(token));
        if ( SKLOG_alloc(&type,unsigned char,sizeof(w)) == SKLOG_FAILURE ) {
            ERROR("SKLOG_alloc() failure");
            goto error;
        }
        memcpy(type,&w,sizeof(w));
        type_len = sizeof(w);

        //~ get data
        token = strtok(NULL,"|");
        tokenl = strlen(token);

        if ( SKLOG_alloc(&enc_data,unsigned char,tokenl) == SKLOG_FAILURE ) {
            ERROR("SKLOG_alloc() failure");
            goto error;
        }

        memcpy(enc_data,token,tokenl);
        enc_data_len = tokenl;

        //~ get hash
        token = strtok(NULL,"|");
        tokenl = strlen(token);

        if ( SKLOG_alloc(&y,unsigned char,tokenl) == SKLOG_FAILURE ) {
            ERROR("SKLOG_alloc() failure");
            goto error;
        }

        memcpy(y,token,tokenl);
        y_len = tokenl;

        //~ get hmac
        token = strtok(NULL,"|");
        tokenl = strlen(token);

        if ( SKLOG_alloc(&z,unsigned char,tokenl) == SKLOG_FAILURE ) {
            ERROR("SKLOG_alloc() failure");
            goto error;
        }

        memcpy(z,token,tokenl-1);
        z_len = tokenl;
        
        SKLOG_free(&line);

        if ( flush_logfile_send_logentry(ssl,f_uuid,type,type_len,
                enc_data,enc_data_len,y,y_len,z,z_len)
                                                    == SKLOG_FAILURE ) {
            ERROR("flush_logfile_send_logentry() failure")
            goto error;
        }

        SKLOG_free(&type);
        SKLOG_free(&enc_data);
        SKLOG_free(&y);
        SKLOG_free(&z);
    }

    fclose(fp);

    if ( localtime_r(&(now->tv_sec),&ts) == NULL ) {
        ERROR("localtime_r() failure");
        goto error;
    }

    if ( strftime(ts_str,SKLOG_SMALL_BUFFER_LEN,"%Y-%m-%d %H:%M:%S",&ts) == 0 ) {
        ERROR("strftime() failure");
        goto error;
    }

    fp = fopen(fname,"a");

    if ( fp == NULL ) {
        ERROR("fopen() failure");
        goto error;
    }

    fprintf(fp,"LOGFILE_CLOSE: %s\n",ts_str);
    fclose(fp);
    
    
    if ( line > 0 ) SKLOG_free(&line);
    return SKLOG_SUCCESS;

error:
    if ( fp > 0 ) fclose(fp);
    if ( line > 0 ) SKLOG_free(&line);
    return SKLOG_FAILURE;
}

SKLOG_RETURN
sklog_file_u_init_logfile(uuid_t            logfile_id,
                            struct timeval    *t)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    struct tm ts;
    char ts_str[SKLOG_SMALL_BUFFER_LEN] = { 0 };
    char f_uuid[UUID_STR_LEN+1] = { 0 };
    char fname[SKLOG_SMALL_BUFFER_LEN] = { 0 };

    FILE *fp = 0;

    //~ compose filename
    uuid_unparse_lower(logfile_id,f_uuid);
    f_uuid[UUID_STR_LEN] = '\0';
    sprintf(fname,"%s/%s.log",SKLOG_U_LOGFILE_PREFIX,f_uuid);

    if ( localtime_r(&(t->tv_sec),&ts) == NULL ) {
        ERROR("localtime_r() failure");
        goto error;
    }

    if ( strftime(ts_str,SKLOG_SMALL_BUFFER_LEN,"%Y-%m-%d %H:%M:%S",&ts) == 0 ) {
        ERROR("strftime() failure");
        goto error;
    }

    fp = fopen(fname,"w+");

    if ( fp == NULL ) {
        ERROR("unable to open file");
        goto error;
    } 

    fprintf(fp,"LOGFILE_OPEN: %s\n",ts_str);
    fclose(fp);

    return SKLOG_SUCCESS;

error:
    fclose(fp);
    return SKLOG_FAILURE; 
}

/*--------------------------------------------------------------------*/
/*                             t                                      */
/*--------------------------------------------------------------------*/

SKLOG_RETURN
sklog_file_t_store_authkey(char             *u_ip,
                           uuid_t           logfile_id,
                           unsigned char    *authkey)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    TO_IMPLEMENT;

    return SKLOG_TO_IMPLEMENT;
}

SKLOG_RETURN
sklog_file_t_store_logentry(unsigned char    *blob,
                            unsigned int     blob_len)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    TO_IMPLEMENT;

    return SKLOG_TO_IMPLEMENT;
}
