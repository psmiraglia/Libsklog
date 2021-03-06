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

#ifndef SKLOG_U_H
#define SKLOG_U_H

#include "sklog_commons.h"

#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <sys/time.h>
#include <uuid/uuid.h>

/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/

#define  SKLOG_U_CONFIG_FILE_PATH  ETC_PREFIX"/libsklog/libsklog-u.conf"
#define  SKLOG_DEF_LOGFILE_SIZE  7
#define  SKLOG_DEF_T_CERT_PATH  ETC_PREFIX"/libsklog/certs/ca/ca_cert.pem"
#define  SKLOG_DEF_T_ADDRESS  "127.0.0.1"
#define  SKLOG_DEF_T_PORT  5555
#define  SKLOG_DEF_U_CERT_PATH  ETC_PREFIX"/libsklog/certs/u1_cert.pem"
#define  SKLOG_DEF_U_RSA_KEY_PATH  ETC_PREFIX"/libsklog/certs/private/u1_key.pem"
#define  SKLOG_DEF_U_TIMEOUT  60

#define  SKLOG_U_CTX_INITIALIZED  1
#define  SKLOG_U_CTX_NOT_INITIALIZED  !SKLOG_U_CTX_INITIALIZED

/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/

typedef struct sklog_u_ctx SKLOG_U_Ctx;
typedef struct sklog_u_storage_driver SKLOG_U_STORAGE_DRIVER;

struct sklog_u_ctx {

    int context_state;

    //~ U information
    char            u_id[HOST_NAME_MAX+1];
    unsigned int    u_id_len;
    int             u_timeout;
    X509            *u_cert;
    EVP_PKEY        *u_privkey;

    //~ T information
    X509            *t_cert;
    char            t_cert_path[512];
    char            t_address[512];
    short int       t_port;

    //~ Logging session information
    int             logfile_size;
    int             logfile_counter;
    uuid_t          logfile_id;

    unsigned char   session_key[SKLOG_SESSION_KEY_LEN];
    unsigned char   auth_key[SKLOG_AUTH_KEY_LEN];
    unsigned char   last_hash_chain[SKLOG_HASH_CHAIN_LEN];

    unsigned char   x0_hash[SHA256_LEN];

    //~ storage driver
    SKLOG_U_STORAGE_DRIVER *lsdriver;

};

struct sklog_u_storage_driver {

    SKLOG_RETURN (*store_logentry)    (uuid_t,SKLOG_DATA_TYPE,
                                       unsigned char *,unsigned int,
                                       unsigned char *,unsigned char *);
    SKLOG_RETURN (*flush_logfile)     (uuid_t,struct timeval *,SSL *);
    SKLOG_RETURN (*init_logfile)      (uuid_t,struct timeval *);
};

/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/

SKLOG_U_Ctx*
SKLOG_U_NewCtx(void);

SKLOG_RETURN
SKLOG_U_FreeCtx(SKLOG_U_Ctx**);

SKLOG_RETURN
SKLOG_U_LogEvent(SKLOG_U_Ctx        *u_ctx,
                 SKLOG_DATA_TYPE    type,
                 char               *data,
                 unsigned int       data_len);

#endif /* SKLOG_U_H */
