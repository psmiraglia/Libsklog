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

#include <netinet/in.h>

SKLOG_RETURN
sklog_file_u_store_logentry(SKLOG_DATA_TYPE    type,
                            unsigned char    *data,
                            unsigned int     data_len,
                            unsigned char    *hash,
                            unsigned char    *hmac)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    //~ todo: store auth_key not in plaintext

    int i = 0;
    int j = 0;

    FILE *fp = fopen(SKLOG_U_LOGFILE,"a+");

    if ( fp == NULL ) {
        ERROR("fopen() failure");
        goto error;
    } 

    char buf_type[9] = { 0 };
    sprintf(buf_type,"%8.8x",htonl(type));

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

    fprintf(fp,"%s|%s|%s|%s\n",buf_type,buf_data,buf_hash,buf_hmac);

    fclose(fp);

    return SKLOG_SUCCESS;

error:
    return SKLOG_FAILURE; 
}  

SKLOG_RETURN
sklog_file_u_flush_logfile(SSL *ssl)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

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

    FILE *fp = fopen(SKLOG_U_LOGFILE,"r");

    if ( fp == NULL ) {
        ERROR("fopen() failure");
        goto error;
    } 

    //~ flush logfile

    while ( ( nread = getline(&line,&dummy,fp) ) != -1 ) {

        //~ get type
        token = strtok(line,"|");
        tokenl = strlen(token);

        if ( SKLOG_alloc(&type,unsigned char,tokenl) == SKLOG_FAILURE ) {
            ERROR("SKLOG_alloc() failure");
            goto error;
        }

        memcpy(type,token,tokenl);
        type_len = tokenl;

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

        memcpy(z,token,tokenl);
        z_len = tokenl;
        
        SKLOG_free(&line);

        /**
         * ALERT: remove NULL
         */
        if ( flush_logfile_send_logentry(ssl,NULL,type,type_len,
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
    if ( line > 0 ) SKLOG_free(&line);
    return SKLOG_SUCCESS;

error:
    if ( fp > 0 ) fclose(fp);
    if ( line > 0 ) SKLOG_free(&line);
    return SKLOG_FAILURE;
}
