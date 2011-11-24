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

#ifndef SKLOG_T_H
#define SKLOG_T_H

#include "sklog_commons.h"

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <sys/time.h>

#include <uuid/uuid.h>

/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/

#define  SKLOG_T_MAX_THREADS     1

#define  SKLOG_T_CONFIG_FILE_PATH  ETC_PREFIX"/libsklog/libsklog-t.conf"
#define  SKLOG_DEF_T_CERT_PATH  ETC_PREFIX"/libsklog/certs/ca/ca_cert.pem"
#define  SKLOG_DEF_T_RSA_KEY_PASSPHRASE  "123456"
#define  SKLOG_DEF_T_RSA_KEY_PATH  ETC_PREFIX"/libsklog/certs/private/ca_key.pem"
#define  SKLOG_DEF_T_ADDRESS  "127.0.0.1"
#define  SKLOG_DEF_T_ID  "t.example.com"
#define  SKLOG_DEF_T_PORT  5555

/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/

typedef struct sklog_t_ctx SKLOG_T_Ctx;
typedef struct sklog_t_storage_driver SKLOG_T_STORAGE_DRIVER;

/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/

struct sklog_t_ctx {

    char            t_id[HOST_NAME_MAX];
    unsigned int    t_id_len;

    const char      *t_address;  // server listen address
    short int       t_port;      // server port address

    X509            *t_cert;
    const char      *t_cert_file_path;
    
    EVP_PKEY        *t_privkey;
    const char      *t_privkey_file_path;

    SKLOG_T_STORAGE_DRIVER *lsdriver;
};

struct sklog_t_storage_driver {
    SKLOG_RETURN (*store_authkey) (char*,uuid_t,unsigned char*);
    SKLOG_RETURN (*store_logentry) (unsigned char*,unsigned int);
    SKLOG_RETURN (*retrieve_logfiles) (unsigned char **,unsigned int *);
    SKLOG_RETURN (*verify_logfile) (unsigned char *);
};

/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/

SKLOG_T_Ctx*
SKLOG_T_NewCtx(void);

SKLOG_RETURN
SKLOG_T_FreeCtx(SKLOG_T_Ctx**);

SKLOG_RETURN
SKLOG_T_InitCtx(SKLOG_T_Ctx    *t_ctx);

SKLOG_RETURN
SKLOG_T_ManageLoggingSessionInit(SKLOG_T_Ctx      *t_ctx,
                                 unsigned char    *m0,
                                 unsigned int     m0_len,
                                 char             *u_address,
                                 unsigned char    **m1,
                                 unsigned int     *m1_len);

SKLOG_RETURN
SKLOG_T_ManageLogfileUpload(SKLOG_T_Ctx         *t_ctx,
                            SKLOG_CONNECTION    *c);


SKLOG_RETURN
SKLOG_T_ManageLogfileRetrieve(SKLOG_T_Ctx         *t_ctx,
                              SKLOG_CONNECTION    *c);

SKLOG_RETURN
SKLOG_T_ManageLogfileVerify(SKLOG_T_Ctx         *t_ctx,
                            SKLOG_CONNECTION    *c,
                            char                *logfile_id);

SKLOG_RETURN
SKLOG_T_RunServer(SKLOG_T_Ctx    *t_ctx);

#endif /* SKLOG_T_H */
