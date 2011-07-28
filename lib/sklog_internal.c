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

#include <netinet/in.h>

#include <openssl/aes.h>
#include <openssl/engine.h>
#include <openssl/err.h>

/*--------------------------------------------------------------------*/
/*                         crypto primitives                          */
/*--------------------------------------------------------------------*/

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

    if ( SKLOG_alloc(&sig,unsigned char,sig_len) == SKLOG_FAILURE ) {
        ERROR("SKLOG_alloc() failure");
        goto error;
    }

    if ( EVP_PKEY_sign(ctx, sig, &sig_len, md, md_len) <= 0 ) {
       ERR_print_errors_fp(stderr);
       goto error;
    }

    /* Signature is sig_len bytes written to buffer sig */
    if ( SKLOG_alloc(signature,unsigned char,sig_len) == SKLOG_FAILURE ) {
        ERROR("SKLOG_alloc() failure");
        goto error;
    }

    memcpy(*signature,sig,sig_len);
    *signature_len = sig_len;

    SKLOG_free(&sig);
    EVP_PKEY_CTX_free(ctx);
    ERR_free_strings();

    #ifdef HAVE_NOTIFY
    NOTIFY("signature process successful")
    #endif

    return SKLOG_SUCCESS;

error:
    if ( sig > 0 ) SKLOG_free(sig);
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
    OpenSSL_add_all_algorithms();
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
        WARNING("EVP_PKEY_CTX_set_rsa_padding")
        ERR_print_errors_fp(stderr);
        goto error;
    }

    /* Determine buffer length */

    retval = EVP_PKEY_decrypt(ctx, NULL, out_len, in, in_len);


    if ( retval <= 0 ) {
        WARNING("EVP_PKEY_decrypt 1")
        if ( retval == -2 )
            WARNING("unsupported")
        ERR_print_errors_fp(stderr);
        goto error;
    }

    if ( (*out = OPENSSL_malloc(*out_len)) == NULL ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    retval = EVP_PKEY_decrypt(ctx, *out, out_len, in, in_len);

    if ( retval <= 0 ) {
        WARNING("EVP_PKEY_decrypt 2")
        if ( retval == -2 )
            WARNING("unsupported")
        SKLOG_free(out);
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
aes256_encrypt(unsigned char    *plain,
               unsigned int     plain_len,
               unsigned char    *key,
               unsigned int     key_len,
               unsigned char    **cipher,
               unsigned int     *cipher_len)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    int ret = 0;
    
    int rounds = 5;
    unsigned char enc_key[AES_KEYSIZE_256] = { 0 };
    unsigned char iv[AES_BLOCK_SIZE] = { 0 };
    unsigned char salt[8] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07};

    EVP_CIPHER_CTX ctx;
    int c_len = 0;
    int f_len = 0;

    OpenSSL_add_all_digests();
    ERR_load_crypto_strings();


    //~ derive encryption key
    
    ret = EVP_BytesToKey(EVP_aes_256_cbc(),EVP_sha256(),
                         salt,
                         key,key_len,
                         rounds,
                         enc_key,iv);
    
    if ( ret != AES_KEYSIZE_256 ) {
        fprintf(stderr,
            "ERROR: EVP_BytesToKey(): key len is %d Bytes (it shloud be 32 Bytes)\n",
            ret);
        return SKLOG_FAILURE;
    }

    //~ initialize EVP context

    EVP_CIPHER_CTX_init(&ctx);

    if ( !EVP_EncryptInit_ex(&ctx,EVP_aes_256_cbc(),NULL,enc_key,iv) ) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_cleanup(&ctx);
        return SKLOG_FAILURE;
    }

    //~ allocate memory for the cipher-text
    
    c_len = plain_len+EVP_CIPHER_CTX_block_size(&ctx);
    *cipher = calloc(c_len,sizeof(char));

    if ( *cipher == NULL ) {
        fprintf(stderr,
            "ERROR: calloc(): failure");
        return SKLOG_FAILURE;
    }

    //~ encrypt plain-text

    if ( !EVP_EncryptUpdate(&ctx,*cipher,&c_len,plain,plain_len)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_cleanup(&ctx);
        return SKLOG_FAILURE;
    }

    if ( !EVP_EncryptFinal_ex(&ctx,*cipher+c_len,&f_len) ) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_cleanup(&ctx);
        return SKLOG_FAILURE;
    }

    *cipher_len = c_len + f_len;

    //~ some free's
    
    EVP_CIPHER_CTX_cleanup(&ctx);
    ERR_free_strings();

    return SKLOG_SUCCESS;
}

SKLOG_RETURN
aes256_decrypt(unsigned char    *cipher,
               unsigned int     cipher_len,
               unsigned char    *key,
               unsigned int     key_len,
               unsigned char    **plain,
               unsigned int     *plain_len)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    int ret = 0;
    
    int rounds = 5;
    unsigned char enc_key[AES_KEYSIZE_256] = { 0 };
    unsigned char iv[AES_BLOCK_SIZE] = { 0 };
    unsigned char salt[8] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07};

    EVP_CIPHER_CTX ctx;

    int p_len = 0;
    int f_len = 0;

    OpenSSL_add_all_digests();
    ERR_load_crypto_strings();

    //~ derive decryption key

    ret = EVP_BytesToKey(EVP_aes_256_cbc(),EVP_sha256(),
                         salt,
                         key,key_len,
                         rounds,
                         enc_key,iv);
    
    if ( ret != AES_KEYSIZE_256 ) {
        fprintf(stderr,
            "ERROR: EVP_BytesToKey(): key len is %d Bytes (it shloud be 32 Bytes)\n",
            ret);
        return SKLOG_FAILURE;
    }

    //~ initialize EVP context

    EVP_CIPHER_CTX_init(&ctx);

    if ( !EVP_DecryptInit_ex(&ctx,EVP_aes_256_cbc(),NULL,enc_key,iv) ) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_cleanup(&ctx);
        return SKLOG_FAILURE;
    }

    //~ allocate memory for the plain-text
    
    p_len = cipher_len;
    *plain = calloc(p_len,sizeof(char));

    if ( *plain == NULL ) {
        fprintf(stderr,
            "ERROR: calloc(): failure");
        return SKLOG_FAILURE;
    }

    //~ decrypt cipher-text

    if ( !EVP_DecryptUpdate(&ctx,*plain,&p_len,cipher,cipher_len)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_cleanup(&ctx);
        return SKLOG_FAILURE;
    }

    if ( !EVP_DecryptFinal_ex(&ctx,*plain+p_len,&f_len) ) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_cleanup(&ctx);
        return SKLOG_FAILURE;
    }

    *plain_len = p_len + f_len;

    //~ some free's
    
    EVP_CIPHER_CTX_cleanup(&ctx);
    ERR_free_strings();

    return SKLOG_SUCCESS;
}

/*--------------------------------------------------------------------*/
/*                         tlv management                             */
/*--------------------------------------------------------------------*/

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
        WARNING("Message not well formed!!!")
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
tlv_parse_message(unsigned char    *msg,
                  uint32_t         expected_type,
                  uint32_t         *type,
                  unsigned int     *len,
                  unsigned char    **value)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    uint32_t t = 0;
    unsigned int l = 0;
    unsigned char *v = 0;

    if ( msg == NULL ) {
        ERROR("msg must be not null")
        goto error;
    }

    if ( tlv_get_type(msg,&t) == SKLOG_FAILURE ) {
        ERROR("tlv_get_type() failure");
        goto error;
    }
    if ( expected_type != NOTYPE ) {
        if ( t != expected_type ) {
            ERROR("malformed message");
            goto error;
        }
    }

    if ( tlv_get_len(msg,&l) == SKLOG_FAILURE ) {
        ERROR("tlv_get_len() failure");
        goto error;
    }

    if ( tlv_get_value(msg,l,&v) == SKLOG_FAILURE ) {
        ERROR("tlv_get_value() failure");
        goto error;
    }

    *type = t;
    *len = l;
    *value = v;

    return SKLOG_SUCCESS;

error:
    return SKLOG_FAILURE;
}                  

SKLOG_RETURN
tlv_create_message(uint32_t         type,
                   unsigned int     len,
                   unsigned char    *value,
                   unsigned int     *message_len,
                   unsigned char    **message)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    uint32_t t = 0;
    unsigned int l = 0;

    if ( value == NULL ) {
        goto error;
    }

    t = htonl(type);
    l = htonl(len);

    *message = calloc(len+8,sizeof(char));

    if ( *message == NULL ) {
        goto error;
    }

    memcpy(*message,value,len+8);
    *message_len = len + 8;
    
    return SKLOG_SUCCESS;

error:
    return SKLOG_FAILURE;
}

/*--------------------------------------------------------------------*/
/*                      timestamp management                          */
/*--------------------------------------------------------------------*/

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
    
    if ( SKLOG_alloc(buf,unsigned char,*buf_len) == SKLOG_FAILURE ) {
        ERROR("SKLOG_alloc() failure");
        return SKLOG_FAILURE;
    }
    
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

/*--------------------------------------------------------------------*/
/*                       memory management                            */
/*--------------------------------------------------------------------*/

SKLOG_RETURN
mem_alloc_n(void      **mem,
            size_t    size,
            size_t    count)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    *mem = calloc(count,size);
    if (*mem == NULL)
        return SKLOG_FAILURE;
    return SKLOG_SUCCESS;
}

SKLOG_RETURN
mem_free(void      **mem)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    free(*mem);
    *mem = NULL;

    return SKLOG_SUCCESS;
}

/*--------------------------------------------------------------------*/
/*                     logfile flush management                       */
/*--------------------------------------------------------------------*/

SKLOG_RETURN
flush_logfile_send_logentry(SSL              *ssl,
                            char             *f_uuid,
                            unsigned char    *type,
                            unsigned int     type_len,
                            unsigned char    *data_enc,
                            unsigned int     data_enc_len,
                            unsigned char    *y,
                            unsigned int     y_len,
                            unsigned char    *z,
                            unsigned int     z_len)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    unsigned char msg[SKLOG_BUFFER_LEN] = { 0 };
    unsigned char buf[SKLOG_BUFFER_LEN] = { 0 };
    unsigned int displacement = 0;

    int nread = 0;
    int nwrite = 0;

    SSL_load_error_strings();

    //~ [ID_LOG][W][DATA][Y][Z]

    if ( tlv_create(ID_LOG,strlen(f_uuid),f_uuid,
                    &buf[displacement]) == SKLOG_FAILURE ) {
        ERROR("tlv_create() failure")
        goto error;
    }
    displacement += (strlen(f_uuid)+8);

    if ( tlv_create(LOGENTRY_TYPE,type_len,type,
                    &buf[displacement]) == SKLOG_FAILURE ) {
        ERROR("tlv_create() failure")
        goto error;
    }
    displacement += type_len+8;
    
    if ( tlv_create(LOGENTRY_DATA,data_enc_len,data_enc,
                    &buf[displacement]) == SKLOG_FAILURE ) {
        ERROR("tlv_create() failure")
        goto error;
    }
    displacement += data_enc_len+8;
    
    if ( tlv_create(LOGENTRY_HASH,y_len,y,
                    &buf[displacement]) == SKLOG_FAILURE ) {
        ERROR("tlv_create() failure")
        goto error;
    }
    displacement += y_len+8;
    
    if ( tlv_create(LOGENTRY_HMAC,z_len,z,
                    &buf[displacement]) == SKLOG_FAILURE ) {
        ERROR("tlv_create() failure")
        goto error;
    }
    displacement += z_len+8;

    if ( tlv_create(LOGENTRY,displacement,buf,msg) == SKLOG_FAILURE ) {
        ERROR("tlv_create() failure")
        goto error;
    }

    nwrite = SSL_write(ssl,msg,displacement+8);
    
    if ( nwrite <= 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    memset(msg,0,SKLOG_BUFFER_LEN);
    nread = SSL_read(ssl,msg,SKLOG_BUFFER_LEN-1);

    if ( nread <= 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    } 

    if ( memcmp(msg,"LE_ACK",6) == 0 ) {
        ERR_free_strings();
        return SKLOG_SUCCESS;
    } else if ( memcmp(msg,"LE_NACK",7) == 0 ) {
        WARNING("received NACK")
        goto error;
    } else {
        ERROR("unexpected message")
        goto error;
    }
    
error:
    ERR_free_strings();
    return SKLOG_FAILURE;
}
