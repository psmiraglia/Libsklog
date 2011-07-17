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

#ifndef SKLOG_COMMONS_H
#define SKLOG_COMMONS_H

#include <config.h>

#include <openssl/ssl.h>

#define DEBUG { \
    fprintf(stderr,"[DEBUG] Libsklog (%s:%d): %s()\n", \
    __FILE__,__LINE__,__func__); \
}

#define ERROR(msg) { \
    fprintf(stderr,"[ERROR] Libsklog (%s:%d): %s(): %s\n", \
    __FILE__,__LINE__,__func__,msg); \
}

#define NOTIFY(msg) { \
    fprintf(stderr,"[NOTIFY] Libsklog (%s:%d): %s(): %s\n", \
    __FILE__,__LINE__,__func__,msg); \
}

#define WARNING(msg) { \
    fprintf(stderr,"[WARNING] Libsklog (%s): %s\n", \
    __func__,msg); \
}

#define SHOWBUF(buf,buf_size) { \
    int w = 0; \
    for ( w = 0 ; w < buf_size ; w++) \
        fprintf(stderr,"%2.2x ",buf[w]); \
    fprintf(stderr,"\n"); \
}
                              
#define OPENSSL_ERROR(e) { \
    e = ERR_get_error(); \
    ERR_load_crypto_strings();\
    fprintf(stderr,"    OPENSSL_ERROR: %s(): %s | %s | %s\n",\
        __func__,\
        ERR_lib_error_string(e),\
        ERR_func_error_string(e),\
        ERR_reason_error_string(e) );\
    ERR_free_strings();\
}

#define SKLOG_CALLOC(mem_ptr,len,type) {\
    mem_ptr = calloc(len,sizeof(type));\
    if ( mem_ptr == NULL ) {\
        ERROR("calloc() failure")\
        exit(1);\
    }\
}

#define SKLOG_FREE(mem_ptr) {\
    free(mem_ptr);\
    mem_ptr = 0;\
}

/* libsklog defines --------------------------------------------------*/

#define     SHA1_LEN        20
#define     SHA256_LEN      32
#define     UUID_LEN        16
#define     UUID_STR_LEN    32
#define     HOST_NAME_MAX   64
#define     AES_KEYSIZE_256 32

#define     SKLOG_BUFFER_LEN          10240  // 10KB
#define     SKLOG_SMALL_BUFFER_LEN    1024   // 1KB
#define     SKLOG_LOG_ID_LEN          UUID_STR_LEN

#define     SKLOG_SESSION_KEY_LEN   SHA256_LEN
#define     SKLOG_AUTH_KEY_LEN      SHA256_LEN
#define     SKLOG_ENC_KEY_LEN       SHA256_LEN
#define     SKLOG_HASH_CHAIN_LEN    SHA256_LEN
#define     SKLOG_HMAC_LEN          SHA256_LEN
#define     SKLOG_DATA_TYPE_SIZE    sizeof(SKLOG_DATA_TYPE)
#define     SKLOG_TIMEOUT           60  /* seconds */

#define     SKLOG_SUCCESS           1
#define     SKLOG_FAILURE           !SKLOG_SUCCESS
#define     SKLOG_TO_IMPLEMENT      SKLOG_SUCCESS

/* libsklog types ----------------------------------------------------*/

typedef int SKLOG_RETURN;
typedef int SKLOG_PROTOCOL_STEP;

typedef enum {
    LogfileInitializationType   = 0x00000000,
    ResponseMessageType         = 0x00000011,
    
    NoType                      = 0x11223344,

    AbnormalCloseType           = 0x00000022,
    NormalCloseMessage          = 0xffffffff,
} SKLOG_DATA_TYPE;

typedef enum {
    A0_KEY           = 0x00000000,
    CERT_U           = 0x00000001,
    TIMESTAMP        = 0x00000002,
    D0_BUF           = 0x00000003,
    ENC_K0           = 0x00000004,
    ENC_K1           = 0x00000005,
    HASH_X0          = 0x00000006,
    ID_LOG           = 0x00000007,
    ID_T             = 0x00000008,
    ID_U             = 0x00000009,
    K0_KEY           = 0x0000000a,
    K1_KEY           = 0x0000000b,
    M0_MSG           = 0x0000000c,
    M1_MSG           = 0x0000000d,
    PROTOCOL_STEP    = 0x0000000e,
    PKE_PUB_T        = 0x0000000f,
    PKE_PUB_U        = 0x00000010,
    X0_BUF           = 0x00000011,
    X0_SIGN_U        = 0x00000012,
    X1_BUF           = 0x00000013,
    X1_SIGN_T        = 0x00000014,

    LOGENTRY_TYPE    = 0x00000015,
    LOGENTRY_DATA    = 0x00000016,
    LOGENTRY_HASH    = 0x00000017,
    LOGENTRY_HMAC    = 0x00000018,
    LOGENTRY         = 0x00000019,
    LE_FLUSH_START   = 0x0000001a,
    LE_FLUSH_END     = 0x0000001b,
    LE_ACK           = 0x0000001c,
    LE_NACK          = 0x0000001d,

    X509_CERT        = 0x000000fc,
} SKLOG_TLV_TYPE;

typedef struct sklog_le {
    //~ unsigned char type[SKLOG_DATA_TYPE_SIZE];
    SKLOG_DATA_TYPE type;
    unsigned char *data_enc;
    unsigned int data_enc_len;
    unsigned char hash[SKLOG_HASH_CHAIN_LEN];
    unsigned char hmac[SKLOG_HMAC_LEN];
} SKLOG_LE;

typedef struct sklog_connection {
    SSL        *ssl;
    SSL_CTX    *ssl_ctx;
    int        socket;
} SKLOG_CONNECTION;

#endif /* SKLOG_COMMONS_H */
