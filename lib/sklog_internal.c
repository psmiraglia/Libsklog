/*
 * Copyright (C) 2010 Politecnico di Torino, Italy
 *                    TORSEC group -- http://security.polito.it
 *
 * Author: Paolo Smiraglia <paolo.smiraglia@polito.it>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 */

#include "../config.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <openssl/blowfish.h>
#include <openssl/des.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/aes.h>

#include "sklog_internal.h"

/**
 * gen_enc_key()
 * Generate encryption key for the current log entry
 * 
 */
int
gen_enc_key(SKCTX *ctx,
            unsigned char *enc_key,
            SKLOG_DATA_TYPE type)
{
    #ifdef TRACE
    fprintf(stdout,"\tgen_enc_key(): ");
    #endif
    
    unsigned char *buffer = 0;
    unsigned int buflen = 0;
    unsigned int pos = 0;

    buflen = sizeof(type) + SK_AUTH_KEY_LEN;
    buffer = calloc(buflen,sizeof(unsigned char));

    memcpy(&buffer[pos],&type,sizeof(type));
    pos+=sizeof(type);
    memcpy(&buffer[pos],ctx->auth_key,SK_AUTH_KEY_LEN);

    /* make sha1 message digest */
    
    EVP_MD_CTX mdctx;
    EVP_MD_CTX_init(&mdctx);
    EVP_DigestInit_ex(&mdctx, EVP_sha256(),NULL);
    EVP_DigestUpdate(&mdctx,buffer,buflen);
    EVP_DigestFinal_ex(&mdctx,enc_key,&buflen);
    EVP_MD_CTX_cleanup(&mdctx);
    
    free(buffer);

    #ifdef TRACE
    int i = 0;
    for ( i = 0 ; i < SK_ENC_KEY_LEN ; i++)
        fprintf(stdout,"%2.2x",enc_key[i]);
    fprintf(stdout,"\n");
    #endif

    return SK_SUCCESS;
}

/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/

/**
 * enc_data_aes256()
 * Encrypt data using AES256
 * 
 */
int
enc_data_aes256(unsigned char **data_enc,
                unsigned int   *data_enc_size,
                unsigned char *data,
                unsigned int   data_size,
                unsigned char *enc_key)
{  
    #ifdef TRACE
    fprintf(stdout,"\tenc_data_aes256(): ");
    #endif
    
    EVP_CIPHER_CTX ctx;
    unsigned char key[32] = { 0 };
    unsigned char iv[32] = { 0 };
    
    /* to manage better */
    unsigned char salt[8] = { 0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88 };
    
    int i = 0;
    int c_len = 0; /* ciphertext len */
    int f_len = 0; /* final len */
    unsigned char *ciphertext = 0;
    
    /* init context */
       
    i = EVP_BytesToKey(EVP_aes_256_cbc(),EVP_sha256(),salt,enc_key,
                       SK_AUTH_KEY_LEN,5,key,iv);
    if ( i != 32 ) {
        fprintf(stderr,"ERR: enc_data_aes256(): Key size is %d bits. \
It should be 256 bits\n", i*8);
        return SK_FAILURE;
    }
    
    EVP_CIPHER_CTX_init(&ctx);
    EVP_EncryptInit_ex(&ctx,EVP_aes_256_cbc(),NULL,key,iv);
    
    /* do encryption */
    
    c_len = data_size + AES_BLOCK_SIZE ;
    ciphertext = calloc(c_len,sizeof(char));
    
    EVP_EncryptInit_ex(&ctx,NULL,NULL,NULL,NULL);
    
    EVP_EncryptUpdate(&ctx,ciphertext,&c_len,data,data_size);
    
    EVP_EncryptFinal_ex(&ctx,ciphertext+c_len,&f_len);
    
    *data_enc_size = c_len + f_len;
    
    *data_enc = calloc(c_len + f_len,sizeof(char));
    memcpy(*data_enc,ciphertext,c_len + f_len);
    
    #ifdef TRACE
    for ( i = 0 ; i < c_len + f_len ; i++)
        fprintf(stdout,"%2.2x",ciphertext[i]);
    fprintf(stdout,"\n");
    #endif
    
    free(ciphertext);
    EVP_CIPHER_CTX_cleanup(&ctx);
    
    return SK_SUCCESS; 
}

/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/

/**
 * dec_data_aes256()
 * Decrypt data encrypted using AES256
 * 
 */
int
dec_data_aes256(unsigned char **data_dec, /* out */
                unsigned int   *data_dec_size, /* out */
                unsigned char *data_enc, /* in */
                unsigned int   data_enc_size, /* in */
                unsigned char *dec_key) /* in */
{
    #ifdef TRACE
    fprintf(stdout,"\tdec_data_aes256():\n");
    #endif
    
    EVP_CIPHER_CTX ctx;
    unsigned char key[32] = { 0 };
    unsigned char iv[32] = { 0 };
    unsigned char salt[8] = { 0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88 };
    int i = 0;
    
    /* init context */
    
    i = EVP_BytesToKey(EVP_aes_256_cbc(),EVP_sha256(),salt,dec_key,
                       SK_AUTH_KEY_LEN,5,key,iv);
    if ( i != 32 ) {
        fprintf(stderr,"ERR: dec_data_aes256(): Key size is %d bits. \
It should be 256 bits\n", i*8);
        return SK_FAILURE;
    }
    
    EVP_CIPHER_CTX_init(&ctx);
    EVP_DecryptInit_ex(&ctx,EVP_aes_256_cbc(),NULL,key,iv);
    
    /* do decription */
    
    int p_len = data_enc_size; /* plaintext len */
    int f_len = 0; /* final len */
    unsigned char *plaintext = 0;
    
    plaintext = calloc(p_len,sizeof(char));
  
    EVP_DecryptInit_ex(&ctx, NULL, NULL, NULL, NULL);
    EVP_DecryptUpdate(&ctx, plaintext, &p_len, data_enc,data_enc_size);
    EVP_DecryptFinal(&ctx, plaintext+p_len, &f_len);

    *data_dec_size = p_len + f_len;
    *data_dec = calloc(p_len + f_len,sizeof(char));
    memcpy(*data_dec,plaintext,p_len + f_len);
    
    free(plaintext);
    EVP_CIPHER_CTX_cleanup(&ctx);
    
    return SK_SUCCESS;  
}

/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/

/**
 * enc_data_des()
 * Encrypt data using DES
 * NOT IN USE
 * 
 */
int /* use aes */
enc_data_des(unsigned char **data_enc,
             unsigned int   *data_enc_size,
             unsigned char *data,
             unsigned int   data_size,
             unsigned char *enc_key)
{
    #ifdef TRACE
    fprintf(stdout,"\tenc_data_des()\n");
    #endif
    
    DES_cblock ivect;
    DES_key_schedule schedule;
    int n = 0;

    *data_enc = calloc(data_size,sizeof(char));
    *data_enc_size = data_size;

    /* Prepare the key for use with DES_cfb64_encrypt */
    memcpy(ivect,enc_key,8);
    DES_set_odd_parity( &ivect );
    DES_set_key_checked( &ivect, &schedule);

    /* Encryption occurs here */
    DES_cfb64_encrypt(data,*data_enc,data_size,&schedule,
                      &ivect,&n,DES_ENCRYPT);

    return SK_SUCCESS;
}

/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/

/**
 * dec_data_des()
 * Decrypt data encrypted using DES
 * NOT IN USE
 * 
 */
int /* use aes */
dec_data_des(unsigned char **data_dec,
             unsigned int   *data_dec_size,
             unsigned char *data_enc,
             unsigned int   data_enc_size,
             unsigned char *dec_key)
{
    #ifdef TRACE
    fprintf(stdout,"\tdec_data_des()\n");
    #endif
    
    DES_cblock ivect;
    DES_key_schedule schedule;
    int n = 0;

    *data_dec = calloc(data_enc_size,sizeof(char));
    *data_dec_size = data_enc_size;

    /* Prepare the key for use with DES_cfb64_encrypt */
    memcpy(ivect,dec_key,8);
    DES_set_odd_parity( &ivect );
    DES_set_key_checked( &ivect, &schedule);

    /* Encryption occurs here */
    DES_cfb64_encrypt(data_enc,*data_dec,data_enc_size,&schedule,
                      &ivect,&n,DES_DECRYPT);

    return SK_SUCCESS;
}

/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/

/**
 * gen_hahs_chain()
 * Generate the hash chain element for the current log entry
 * 
 */
int
gen_hash_chain(SKCTX *ctx,
               unsigned char *hash_chain,
               unsigned char *data_enc,
               unsigned int data_enc_size,
               SKLOG_DATA_TYPE type)
{
    #ifdef TRACE
    fprintf(stdout,"\tgen_hash_chain(): ");
    #endif
    
    unsigned char *buffer = 0;
    unsigned int buflen = 0;
    unsigned int pos = 0;

    buflen = sizeof(type) + data_enc_size + SK_HASH_CHAIN_LEN;
    buffer = calloc(buflen,sizeof(unsigned char));

    memcpy(&buffer[pos],ctx->last_hash_chain,SK_HASH_CHAIN_LEN);
    pos+=SK_HASH_CHAIN_LEN;
    memcpy(&buffer[pos],data_enc,data_enc_size);
    pos+=data_enc_size;
    memcpy(&buffer[pos],&type,sizeof(type));

    /* make sha1 message digest */
    
    EVP_MD_CTX mdctx;
    EVP_MD_CTX_init(&mdctx);
    EVP_DigestInit_ex(&mdctx, EVP_sha256(),NULL);
    EVP_DigestUpdate(&mdctx,buffer,buflen);
    EVP_DigestFinal_ex(&mdctx,hash_chain,&buflen);
    EVP_MD_CTX_cleanup(&mdctx);
    
    /* save hash chain for the next generation */
    memcpy(ctx->last_hash_chain,hash_chain,SK_HASH_CHAIN_LEN);

    #ifdef TRACE
    int i = 0;
    for ( i = 0 ; i < SK_HASH_CHAIN_LEN ; i++)
        fprintf(stdout,"%2.2x",ctx->last_hash_chain[i]);
    fprintf(stdout,"\n");
    #endif

    free(buffer);

    return SK_SUCCESS;
}

/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/

/**
 * gen_hmac()
 * Generate the hmac for the current log entry
 * 
 */
int
gen_hmac(SKCTX *ctx,
         unsigned char *hmac,
         unsigned char *hash_chain)
{
    //~ #ifdef TRACE
    //~ int i = 0;
    //~ fprintf(stdout,"\tgen_hmac(): generating hmac using auth_key: ");
    //~ for(i = 0 ; i < SK_AUTH_KEY_LEN ; i++)
        //~ fprintf(stdout,"%2.2x",ctx->auth_key[i]);
    //~ fprintf(stdout,"\n");
    //~ #endif
    
    #ifdef TRACE
    fprintf(stdout,"\tgen_hmac(): ");
    #endif

    /* make hmac using sha256 digest */
    
    unsigned int hmac_len = 0;
    
    HMAC_CTX mdctx;
    HMAC_CTX_init(&mdctx);
    HMAC_Init_ex(&mdctx,ctx->auth_key,SK_AUTH_KEY_LEN,EVP_sha256(),NULL);
    HMAC_Update(&mdctx,hash_chain,SK_HASH_CHAIN_LEN);
    HMAC_Final(&mdctx,hmac,&hmac_len);
    HMAC_CTX_cleanup(&mdctx);
    
    #ifdef TRACE
    int i = 0;
    for(i = 0 ; i < SK_HMAC_LEN ; i++)
        fprintf(stdout,"%2.2x",hmac[i]);
    fprintf(stdout,"\n");
    #endif

    return SK_SUCCESS;
}

/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/

/**
 * renew_auth_key()
 * Renew the auth_key 
 * 
 */
int
renew_auth_key(SKCTX *ctx)
{
    #ifdef TRACE
    fprintf(stdout,"\trenew_auth_key(): ");
    #endif
    
    unsigned char *buffer = 0;
    unsigned int buflen = 0;

    buffer = calloc(SK_AUTH_KEY_LEN,sizeof(unsigned char));
    memcpy(buffer,ctx->auth_key,SK_AUTH_KEY_LEN);
    
    /* make sha1 message digest */
    
    EVP_MD_CTX mdctx;
    EVP_MD_CTX_init(&mdctx);
    EVP_DigestInit_ex(&mdctx, EVP_sha256(),NULL);
    EVP_DigestUpdate(&mdctx,buffer,SK_AUTH_KEY_LEN);
    EVP_DigestFinal_ex(&mdctx,ctx->auth_key,&buflen);
    EVP_MD_CTX_cleanup(&mdctx);
    
    free(buffer);

    #ifdef TRACE
    int i = 0;
    for(i = 0 ; i < SK_AUTH_KEY_LEN ; i++)
        fprintf(stdout,"%2.2x",ctx->auth_key[i]);
    fprintf(stdout,"\n");
    #endif

    return SK_SUCCESS;
}

/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/

/**
 * gen_log_entry()
 * NOT IN USE
 * 
 */
/*
int
gen_log_entry(unsigned char **log_entry,
              unsigned int *log_entry_size,
              SKLOG_DATA_TYPE type,
              unsigned char *enc_data,
              unsigned int enc_data_size,
              unsigned char *hash_chain,
              unsigned char *mac)
{
    #ifdef TRACE
    fprintf(stdout,"\tgen_log_entry()\n");
    #endif
    
    unsigned int len = 0;
    unsigned int pos = 0;

    len = sizeof(type) + enc_data_size + SK_HASH_CHAIN_LEN + SK_HMAC_LEN;

    *log_entry = calloc(len,sizeof(char));

    if ( *log_entry != 0 ) {
        memcpy(*log_entry+pos,&type,sizeof(type));
        pos+=sizeof(type);
        memcpy(*log_entry+pos,enc_data,enc_data_size);
        pos+=enc_data_size;
        memcpy(*log_entry+pos,hash_chain,SK_HASH_CHAIN_LEN);
        pos+=SK_HASH_CHAIN_LEN;
        memcpy(*log_entry+pos,mac,SK_HMAC_LEN);
        pos+=SK_HMAC_LEN;

        *log_entry_size = pos;
        return SK_SUCCESS;
    } else {
        fprintf(stderr,"ERR: gen_log_entry(): calloc() fail!\n");
        return SK_FAILURE;
    }
}
*/

/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/

/**
 * write_log_entry()
 * NOT IN USE
 * 
 */
/*
int
write_log_entry(unsigned char *log_entry,
                unsigned int log_entry_size)
{
    #ifdef TRACE
    fprintf(stdout,"\twrite_log_entry()\n");
    #endif
    
    int fd = 0;
    char buffer[BUFLEN] = { 0 };
    int i = 0;
    int j = 0;

    for ( ; i < log_entry_size ; i++ ) {
        sprintf(&buffer[j],"%2.2x",log_entry[i]);
        j+=2;
    }

    fd = open(SK_LOGFILE_PATH,O_WRONLY|O_APPEND|O_CREAT,S_IRWXU);

    if (fd > 0 ) {
        write(fd,&buffer,log_entry_size*2);
        write(fd,"\n",1);
        close(fd);
        return SK_FAILURE;
    }
    return SK_SUCCESS;
}
*/

/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/

/**
 * gen_nonce()
 * 
 */
int
gen_nonce(unsigned char *nonce,
          SKLOG_DATA_TYPE *type,
          unsigned char *data_enc,
          unsigned int data_enc_size,
          unsigned char *hash_chain,
          unsigned char *hmac)
{
    #ifdef TRACE
    fprintf(stdout,"\tgen_nonce()\n");
    #endif
    
    unsigned char *buffer = 0;
    unsigned int buflen = 0;
    unsigned int pos = 0;
    
    buflen = SK_LOGENTRY_TYPE_LEN +
             data_enc_size +
             SK_HASH_CHAIN_LEN +
             SK_HMAC_LEN;
    
    buffer = calloc(buflen,sizeof(char));
    
    if ( buffer ) {
        memcpy(buffer+pos,type,SK_LOGENTRY_TYPE_LEN);
        pos += SK_LOGENTRY_TYPE_LEN;
        memcpy(buffer+pos,data_enc,data_enc_size);
        pos += data_enc_size;
        memcpy(buffer+pos,hash_chain,SK_HASH_CHAIN_LEN);
        pos += SK_HASH_CHAIN_LEN;
        memcpy(buffer+pos,hmac,SK_HMAC_LEN);
        pos += SK_HMAC_LEN;
        
        /* make sha1 digest */
        
        EVP_MD_CTX mdctx;
        EVP_MD_CTX_init(&mdctx);
        EVP_DigestInit_ex(&mdctx, EVP_sha1(),NULL);
        EVP_DigestUpdate(&mdctx,buffer,SK_AUTH_KEY_LEN);
        EVP_DigestFinal_ex(&mdctx,nonce,&buflen);
        EVP_MD_CTX_cleanup(&mdctx);
    
        free(buffer);
        
        return SK_SUCCESS;
        
    } else {
        /* calloc error*/
        fprintf(stderr,"ERR: gen_nonce(): calloc() fail!\n");
        return SK_FAILURE;
    } 
}

/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/
