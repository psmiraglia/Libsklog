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

#include "sklog_commons.h"
#include "sklog_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/aes.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>


SKLOG_RETURN
SKLOG_Utils_SerializeLogentry(SKLOG_LE *le,
                              unsigned char **blob,
                              unsigned int *blob_size)
{
    #ifdef DO_TRACE
    DEBUG
    #endif
    
    unsigned int size = SKLOG_DATA_TYPE_SIZE + SKLOG_HASH_CHAIN_LEN +
                        SKLOG_HMAC_LEN + le->data_enc_len;
    unsigned int i = 0;
       
    *blob = calloc(size,sizeof(char));
    
    if ( *blob != NULL ) {
        memcpy(*blob+i,&le->type,SKLOG_DATA_TYPE_SIZE);
        i += SKLOG_DATA_TYPE_SIZE;
        
        memcpy(*blob+i,le->data_enc,le->data_enc_len);
        i += le->data_enc_len;
        
        memcpy(*blob+i,le->hash,SKLOG_HASH_CHAIN_LEN);
        i += SKLOG_HASH_CHAIN_LEN;
        
        memcpy(*blob+i,le->hmac,SKLOG_HMAC_LEN);
                
        *blob_size = size;
        return SKLOG_SUCCESS;
    } else {
        ERROR("calloc() failure")
        return SKLOG_FAILURE;
    }
}

SKLOG_RETURN
SKLOG_Utils_DeserializeLogentry(unsigned char *blob,
                                unsigned int blob_size,
                                SKLOG_LE *le)
{
    #ifdef DO_TRACE
    DEBUG
    #endif
    
    unsigned int i = 0;
    unsigned int data_enc_len = 0;
    
    if ( le != NULL ) {
        
        data_enc_len = blob_size -
                       SKLOG_DATA_TYPE_SIZE -
                       SKLOG_HASH_CHAIN_LEN -
                       SKLOG_HMAC_LEN;
        
        memcpy(&le->type,&blob[i],SKLOG_DATA_TYPE_SIZE);
        i += SKLOG_DATA_TYPE_SIZE;

        le->data_enc = calloc(data_enc_len,sizeof(char));

        if ( le->data_enc == 0 ) {
            ERROR("calloc() failure")
            return SKLOG_FAILURE;
        }
        
        memcpy(le->data_enc,&blob[i],data_enc_len);
        i += data_enc_len;
        
        le->data_enc_len = data_enc_len;
        
        memcpy(le->hash,&blob[i],SKLOG_HASH_CHAIN_LEN);
        i += SKLOG_HASH_CHAIN_LEN;
        
        memcpy(le->hmac,&blob[i],SKLOG_HMAC_LEN);
        i += SKLOG_HMAC_LEN;
        
    } else {
        ERROR("le must be NOT NULL")
        return SKLOG_FAILURE;
    }
    
    return SKLOG_SUCCESS;
}
