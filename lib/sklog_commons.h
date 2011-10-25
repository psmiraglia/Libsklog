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

#if HAVE_CONFIG_H
    #include <config.h>
#endif

#include <unistd.h>

#include <openssl/ssl.h>

#include <sys/types.h>

/*--------------------------------------------------------------------*/
/*                       message macros                               */
/*--------------------------------------------------------------------*/

#define DEBUG { \
    fprintf(stderr,"[DEBUG] (%d) Libsklog (%s:%d): %s()\n", \
    getpid(),__FILE__,__LINE__,__func__); \
}

#define ERROR(msg) { \
    fprintf(stderr,"[ERROR] (%d) Libsklog (%s:%d): %s(): %s\n", \
    getpid(),__FILE__,__LINE__,__func__,msg); \
}

#define NOTIFY(msg) { \
    fprintf(stderr,"[NOTIFY] (%d) Libsklog (%s:%d): %s(): %s\n", \
    getpid(),__FILE__,__LINE__,__func__,msg); \
}

#define WARNING(msg) { \
    fprintf(stderr,"[WARNING] (%d) Libsklog (%s): %s\n", \
    getpid(),__func__,msg); \
}

#define TO_IMPLEMENT {\
    fprintf(stderr,"\n# Function %s() will be implemented as soon as \
possible. Could you help me? :-D\n\n"\
    , __func__); \
}

/*--------------------------------------------------------------------*/
/*                    memory management macros                        */
/*--------------------------------------------------------------------*/

#define SKLOG_alloc(mem,type,count) \
    mem_alloc_n((void **)mem,sizeof(type),count)

#define SKLOG_free(mem) \
    mem_free((void **)mem)
    
/*--------------------------------------------------------------------*/
/*                         common defines                             */
/*--------------------------------------------------------------------*/

#define     SHA1_LEN                  20
#define     SHA256_LEN                32
#define     UUID_LEN                  16
#define     UUID_STR_LEN              36
#define     HOST_NAME_MAX             64
#define     AES_KEYSIZE_256           32

#define     SKLOG_BUFFER_LEN          10240
#define     SKLOG_SMALL_BUFFER_LEN    1024
#define     SKLOG_LOG_ID_LEN          UUID_STR_LEN

#define     SKLOG_SESSION_KEY_LEN     SHA256_LEN
#define     SKLOG_AUTH_KEY_LEN        SHA256_LEN
#define     SKLOG_ENC_KEY_LEN         SHA256_LEN
#define     SKLOG_HASH_CHAIN_LEN      SHA256_LEN
#define     SKLOG_HMAC_LEN            SHA256_LEN

#define     SKLOG_SUCCESS             1
#define     SKLOG_FAILURE             !SKLOG_SUCCESS
#define     SKLOG_TO_IMPLEMENT        SKLOG_SUCCESS

#define     SKLOG_ACK                 "LE_ACK"
#define     SKLOG_ACK_LEN             6

/*--------------------------------------------------------------------*/
/*                              types                                 */
/*--------------------------------------------------------------------*/

typedef     int                            SKLOG_RETURN;
typedef     int                            SKLOG_PROTOCOL_STEP;
typedef     enum       sklog_data_type     SKLOG_DATA_TYPE;
typedef     enum       sklog_tlv_type      SKLOG_TLV_TYPE;
typedef     struct     sklog_connection    SKLOG_CONNECTION;

enum sklog_data_type {
    LogfileInitializationType   = 0x00000000,
    ResponseMessageType         = 0x00000011,
    
    NoType                      = 0x11223344,

    AbnormalCloseType           = 0x00000022,
    NormalCloseMessage          = 0xffffffff,
};

enum sklog_tlv_type {
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

    RETR_LOG_FILES   = 0x0000001e,
    LOG_FILES        = 0x0000001f,

    X509_CERT        = 0x000000fc,

    NOTYPE           = 0xffffffff,
};

struct sklog_connection {
    SSL        *ssl;
    SSL_CTX    *ssl_ctx;
    int        socket;
};

#endif /* SKLOG_COMMONS_H */
