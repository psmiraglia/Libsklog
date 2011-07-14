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

#include <string.h>

#include <netinet/in.h> //~ for htonl(), ntohl(), ...

#include <openssl/aes.h>
#include <openssl/engine.h>
#include <openssl/err.h>

SKLOG_RETURN
sign_message(unsigned char    *message,
             unsigned int     message_len,
             EVP_PKEY         *signing_key,
             unsigned char    **signature,
             unsigned int     *signature_len)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    int retval = 0;

    EVP_PKEY_CTX *ctx = 0;
    unsigned char md[SHA256_LEN] = { 0 };
    unsigned char *sig = 0;
    size_t md_len = SHA256_LEN;
    size_t sig_len = 0;
    EVP_MD_CTX mdctx;

    OpenSSL_add_all_digests();
    ERR_load_crypto_strings();

    //~ generate sha256 message digest
    
    EVP_MD_CTX_init(&mdctx);

    retval = EVP_DigestInit_ex(&mdctx,EVP_sha256(),NULL);
    if ( retval == 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }
    
    retval = EVP_DigestUpdate(&mdctx,message,message_len);
    if ( retval == 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }
    
    retval = EVP_DigestFinal_ex(&mdctx,md,(unsigned int *)&md_len);
    if ( retval == 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }
    
    EVP_MD_CTX_cleanup(&mdctx);

    /*
     * assumes signing_key, md and mdlen are already set up and that
     * signing_key is an RSA private key
     */

    //~ why second argument is NULL? To investigate...
    ctx = EVP_PKEY_CTX_new(signing_key,NULL);

    if ( ctx == NULL ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    if ( EVP_PKEY_sign_init(ctx) <= 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    if ( EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0 ) {
       ERR_print_errors_fp(stderr);
       goto error;
    }

    if ( EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0 ) {
       ERR_print_errors_fp(stderr);
       goto error;
    }

    //~ determine buffer length
    if ( EVP_PKEY_sign(ctx, NULL, &sig_len, md, md_len) <= 0 ) {
       ERR_print_errors_fp(stderr);
       goto error;
    }

    sig = OPENSSL_malloc(sig_len);

    if ( !sig ) {
       ERR_print_errors_fp(stderr);
       goto error;
    }

    if ( EVP_PKEY_sign(ctx, sig, &sig_len, md, md_len) <= 0 ) {
       ERR_print_errors_fp(stderr);
       goto error;
    }

    /* Signature is sig_len bytes written to buffer sig */
    SKLOG_CALLOC(*signature,sig_len,char)

    memcpy(*signature,sig,sig_len);
    *signature_len = sig_len;

    OPENSSL_free(sig);
    EVP_PKEY_CTX_free(ctx);
    ERR_free_strings();

    #ifdef HAVE_NOTIFY
    NOTIFY("signature process successful")
    #endif

    return SKLOG_SUCCESS;

error:
    if ( sig > 0 ) OPENSSL_free(sig);
    if ( ctx > 0 ) EVP_PKEY_CTX_free(ctx);
    ERR_free_strings();
    return SKLOG_FAILURE;
}

SKLOG_RETURN
sign_verify(EVP_PKEY         *verify_key,
            unsigned char    *signature,
            size_t           signature_len,
            unsigned char    *message,
            unsigned int     message_len)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    int retval = 0;
    
    unsigned char md[SHA256_LEN] = { 0 };
    unsigned int md_len = 0;
    EVP_MD_CTX mdctx;

    EVP_PKEY_CTX *ctx = NULL;

    OpenSSL_add_all_digests();
    ERR_load_crypto_strings();
    
    //~ generate sha256 message digest
    EVP_MD_CTX_init(&mdctx);
    
    retval = EVP_DigestInit_ex(&mdctx,EVP_sha256(),NULL);
    if ( retval == 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }
    
    retval = EVP_DigestUpdate(&mdctx,message,message_len);
    if ( retval == 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }
    
    retval = EVP_DigestFinal_ex(&mdctx,md,&md_len);
    if ( retval == 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }
    
    EVP_MD_CTX_cleanup(&mdctx);

    //~ verify signature
    if ( (ctx = EVP_PKEY_CTX_new(verify_key,NULL)) == NULL ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    if ( EVP_PKEY_verify_init(ctx) <= 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    if ( EVP_PKEY_CTX_set_rsa_padding(ctx,RSA_PKCS1_PADDING) <= 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    if ( EVP_PKEY_CTX_set_signature_md(ctx,EVP_sha256()) <= 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    retval = EVP_PKEY_verify(ctx,signature,signature_len,md,md_len);

    if ( retval < 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    if ( retval > 0 ) {
        NOTIFY("signature verification successfull :-D")
        ERR_free_strings();
        return SKLOG_SUCCESS;
    } else {
        NOTIFY("signature verification fails :-(")
    }

error:
    ERR_free_strings();
    return SKLOG_FAILURE;
}

SKLOG_RETURN
pke_encrypt(X509             *cert,
            unsigned char    *in,
            unsigned char    in_len,
            unsigned char    **out,
            size_t           *out_len)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    int retval = 0;

    EVP_PKEY *pubkey = 0;
    EVP_PKEY_CTX *evp_ctx = 0;

    OpenSSL_add_all_digests();
    ERR_load_crypto_strings();

    if ( (pubkey = X509_get_pubkey(cert)) == NULL ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    if ( (evp_ctx = EVP_PKEY_CTX_new(pubkey,NULL)) == NULL ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    retval = EVP_PKEY_encrypt_init(evp_ctx);

    if ( retval <= 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    retval = EVP_PKEY_CTX_set_rsa_padding(evp_ctx,RSA_PKCS1_PADDING);

    if ( retval <= 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    retval = EVP_PKEY_encrypt(evp_ctx,NULL,out_len,in,in_len);

    if ( retval <= 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    if ( (*out = OPENSSL_malloc(*out_len)) == NULL ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    retval = EVP_PKEY_encrypt(evp_ctx,*out,out_len,in,in_len);

    if ( retval <= 0 )  {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    EVP_PKEY_CTX_free(evp_ctx);
    ERR_free_strings();
    return SKLOG_SUCCESS;

error:
    if ( evp_ctx > 0 ) EVP_PKEY_CTX_free(evp_ctx);
    if ( *out > 0 ) OPENSSL_free(*out);
    ERR_free_strings();
    return SKLOG_FAILURE;
}

SKLOG_RETURN
pke_decrypt(EVP_PKEY         *key,
            unsigned char    *in,
            size_t           in_len,
            unsigned char    **out,
            size_t           *out_len)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    int retval = 0;
    
    EVP_PKEY_CTX *ctx = NULL;

    OpenSSL_add_all_digests();
    ERR_load_crypto_strings();

    /*
     * assumes key in, inlen are already set up and that key is an RSA
     * private key
     */

    if ( (ctx = EVP_PKEY_CTX_new(key,NULL)) == NULL ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    retval = EVP_PKEY_decrypt_init(ctx);

    if ( retval <= 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    retval = EVP_PKEY_CTX_set_rsa_padding(ctx,RSA_PKCS1_PADDING);

    if ( retval <= 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    /* Determine buffer length */

    retval = EVP_PKEY_decrypt(ctx, NULL, out_len, in, in_len);

    if ( retval <= 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    if ( (*out = OPENSSL_malloc(*out_len)) == NULL ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    retval = EVP_PKEY_decrypt(ctx, *out, out_len, in, in_len);

    if ( retval <= 0 ) {
        free(*out);
        ERR_print_errors_fp(stderr);
        goto error;
    }

    /* Decrypted data is outlen bytes written to buffer out */

    ERR_free_strings();
    return SKLOG_SUCCESS;

error:
    if ( ctx > 0 ) EVP_PKEY_CTX_free(ctx);
    ERR_free_strings();
    return SKLOG_FAILURE;
}

SKLOG_RETURN
encrypt_aes256(unsigned char    **data_enc,
               unsigned int     *data_enc_size,
               unsigned char    *data,
               unsigned int     data_size,
               unsigned char    *enc_key)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    int retval = 0;

    EVP_CIPHER_CTX ctx;
    unsigned char key[32] = { 0 };
    unsigned char iv[32] = { 0 };
    unsigned char salt[8] = { 1 }; //~ to refine

    int i = 0;
    int c_len = 0; //~ ciphertext len
    int f_len = 0; //~ final len
    unsigned char *ciphertext = 0;

    OpenSSL_add_all_digests();
    ERR_load_crypto_strings();

    //~ init context
    i = EVP_BytesToKey(EVP_aes_256_cbc(),EVP_sha256(),salt,enc_key,
                       SKLOG_AUTH_KEY_LEN,5,key,iv);
    if ( i != 32 ) {
        ERROR("key size should be 256 bits")
        goto error;
    }

    EVP_CIPHER_CTX_init(&ctx);
    retval = EVP_EncryptInit_ex(&ctx,EVP_aes_256_cbc(),NULL,key,iv);

    if ( retval == 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    //~ do encryption
    c_len = data_size +
            AES_BLOCK_SIZE ;

    SKLOG_CALLOC(ciphertext,c_len,char)

    retval = EVP_EncryptInit_ex(&ctx,NULL,NULL,NULL,NULL);
    if ( retval == 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }
    
    retval = EVP_EncryptUpdate(&ctx,ciphertext,&c_len,data,data_size);
    if ( retval == 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }
    
    retval = EVP_EncryptFinal_ex(&ctx,ciphertext+c_len,&f_len);
    if ( retval == 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    *data_enc_size = c_len + f_len;
    SKLOG_CALLOC(*data_enc,*data_enc_size,char)
    memcpy(*data_enc,ciphertext,c_len + f_len);

    SKLOG_FREE(ciphertext);
    EVP_CIPHER_CTX_cleanup(&ctx);

    ERR_free_strings();
    return SKLOG_SUCCESS;
error:
    if ( ciphertext > 0 ) free(ciphertext); 
    EVP_CIPHER_CTX_cleanup(&ctx);
    ERR_free_strings();
    return SKLOG_FAILURE;
}

SKLOG_RETURN
decrypt_aes256(unsigned char    *dec_key,
               unsigned char    *in,
               unsigned int     in_len,
               unsigned char    **out,
               unsigned int     *out_len)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    int retval = 0;

    EVP_CIPHER_CTX ctx;
    unsigned char key[32] = { 0 };
    unsigned char iv[32] = { 0 };
    unsigned char salt[8] = { 1 }; //~ to refine
    int i = 0;

    int p_len = in_len; /* plaintext len */
    int f_len = 0; /* final len */
    unsigned char *plaintext = 0;

    OpenSSL_add_all_digests();
    ERR_load_crypto_strings();

    /* init context */

    if ( (i = EVP_BytesToKey(EVP_aes_256_cbc(),EVP_sha256(),
                             salt,dec_key,
                             SKLOG_AUTH_KEY_LEN,5,key,iv)) != 32 ) {
        //~ error
        goto error;
    }

    EVP_CIPHER_CTX_init(&ctx);
    retval = EVP_DecryptInit_ex(&ctx,EVP_aes_256_cbc(),NULL,key,iv);

    if ( retval == 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    /* do decription */
    plaintext = calloc(p_len,sizeof(char));

    retval = EVP_DecryptInit_ex(&ctx, NULL, NULL, NULL, NULL);
    if ( retval == 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }
    
    retval = EVP_DecryptUpdate(&ctx, plaintext, &p_len, in,in_len);
    if ( retval == 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }
    
    retval = EVP_DecryptFinal(&ctx, plaintext+p_len, &f_len);
    if ( retval == 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    *out_len = p_len + f_len;
    *out = calloc(p_len + f_len,sizeof(char));
    memcpy(*out,plaintext,p_len + f_len);

    free(plaintext);
    EVP_CIPHER_CTX_cleanup(&ctx);
    ERR_free_strings();

    return SKLOG_SUCCESS;

error:
    EVP_CIPHER_CTX_cleanup(&ctx);
    ERR_free_strings();
    return SKLOG_FAILURE;
}

SKLOG_RETURN
tlv_create(uint32_t         type,
           unsigned int     data_len,
           void             *data,
           unsigned char    *buffer)
{
    #ifdef DO_TRACE_X
    DEBUG
    #endif

    /**
     * tlv structure:
     *    4 Bytes: type
     *    4 Bytes: length
     *    $length Bytes: content
     */

    if ( data == NULL ) {
        ERROR("data must be NOT NULL")
        return SKLOG_FAILURE;
    }

    uint32_t tmp = htonl(type);
    uint32_t len = htonl(data_len);

    //~ SKLOG_CALLOC(*tlv,*tlv_len,char)

    memcpy(buffer,&tmp,sizeof(uint32_t));
    memcpy(&buffer[sizeof(uint32_t)],&len,sizeof(uint32_t));
    memcpy(&buffer[sizeof(uint32_t)+sizeof(uint32_t)],data,data_len);

    return SKLOG_SUCCESS;
}

SKLOG_RETURN
tlv_parse(unsigned char    *tlv_msg,
          uint32_t         type,
          void             *data,
          unsigned int     *data_len)
{
    #ifdef DO_TRACE_X
    DEBUG
    #endif

    if ( tlv_msg == NULL ) {
        ERROR("unsigned char *tlv_msg must be NOT NULL")
        return SKLOG_FAILURE;
    }

    #ifdef DO_TRACE_X
    int y = 0;
    for ( y = 0 ; y < 4 ; y++ )
        fprintf(stderr,"%2.2x ",tlv_msg[y]);
    fprintf(stderr,"\n");
    for ( ; y < 8 ; y++ )
        fprintf(stderr,"%2.2x ",tlv_msg[y]);
    fprintf(stderr,"\n");
    #endif

    unsigned int len = 0;

    uint32_t tmp = 0;

    memcpy(&tmp,tlv_msg,4);
    tmp = ntohl(tmp);

    if ( tmp != type ) {
        //~ WARNING("Message not well formed!!!")
        return SKLOG_FAILURE;
    }

    memcpy(&len,&tlv_msg[4],4);
    len = ntohl(len);

    memcpy(data,&tlv_msg[8],len);
    *data_len = len;

    return SKLOG_SUCCESS;
}

SKLOG_RETURN
tlv_get_type(unsigned char    *tlv_msg,
             uint32_t         *type)
{
    uint32_t tmp = 0;

    if ( tlv_msg == 0 ) {
        ERROR("argument 1 must be not null");
        return SKLOG_FAILURE;
    }

    if ( type == 0 ) {
        ERROR("argument 2 must be not null");
        return SKLOG_FAILURE;
    }
        
    memcpy(&tmp,tlv_msg,4);
    *type = ntohl(tmp);
    
    return SKLOG_SUCCESS;
}

SKLOG_RETURN
tlv_get_len(unsigned char    *tlv_msg,
            unsigned int     *len)
{
    unsigned int  tmp = 0;

    if ( tlv_msg == 0 ) {
        ERROR("argument 1 must be not null");
        return SKLOG_FAILURE;
    }

    if ( len == 0 ) {
        ERROR("argument 2 must be not null");
        return SKLOG_FAILURE;
    }
        
    memcpy(&tmp,&tlv_msg[4],4);
    *len = ntohl(tmp);
    
    return SKLOG_SUCCESS;
}

SKLOG_RETURN
tlv_get_value(unsigned char    *tlv_msg,
              unsigned int     len,
              unsigned char    **value)
{
    unsigned char *tmp = 0;

    tmp = calloc(len,sizeof(char));
    memcpy(tmp,&tlv_msg[8],len);
    *value = tmp;

    return SKLOG_SUCCESS;
}

SKLOG_RETURN
serialize_timeval(struct timeval    *time,
                  unsigned char     **buf,
                  unsigned int      *buf_len)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    uint64_t sec = 0;
    uint64_t usec = 0;

    sec = htonl(time->tv_sec);
    usec = htonl(time->tv_usec);

    *buf_len = 2*sizeof(uint64_t);
    SKLOG_CALLOC(*buf,*buf_len,char)
    memcpy(*buf,&sec,sizeof(uint64_t));
    memcpy(*buf+sizeof(uint64_t),&usec,sizeof(uint64_t));
    
    return SKLOG_SUCCESS;
}

SKLOG_RETURN
deserialize_timeval(unsigned char     *buf,
                    unsigned int      buf_len,
                    struct timeval    *time)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    uint64_t sec = 0;
    uint64_t usec = 0;

    memcpy(&sec,buf,sizeof(uint64_t));
    memcpy(&usec,&buf[sizeof(uint64_t)],sizeof(uint64_t));

    time->tv_sec = ntohl(sec);
    time->tv_usec = ntohl(usec);

    return SKLOG_SUCCESS;
}
