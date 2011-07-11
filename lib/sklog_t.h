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

/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/

#define  SKLOG_T_MAX_THREADS     1

#define  SKLOG_T_CONFIG_FILE_PATH  ETC_PREFIX"/libsklog/libsklog-t.conf"
#define  SKLOG_DEF_T_CERT_PATH  ETC_PREFIX"/libsklog/certs/ca/ca_cert.pem"
#define  SKLOG_DEF_T_RSA_KEY_PASSPHRASE  "123456"
#define  SKLOG_DEF_T_RSA_KEY_PATH  ETC_PREFIX"/libsklog/certs/private/ca_key.pem"

#define  SKLOG_T_DB  VAR_PREFIX"/libsklog/db/t.db"

/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/

typedef struct sklog_t_ctx {

    char            t_id[HOST_NAME_MAX];
    unsigned int    t_id_len;

    const char      *t_address; //xxx.xxx.xxx.xxx
    short int       t_port;

    X509            *t_cert;
    const char      *t_cert_path;
    unsigned int    t_cert_size;
    EVP_PKEY        *t_priv_key;
    const char      *t_priv_key_path;
    
} SKLOG_T_Ctx;

/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/

SKLOG_RETURN
SKLOG_T_InitCtx(SKLOG_T_Ctx    *t_ctx);

SKLOG_RETURN
SKLOG_T_Run(SKLOG_T_Ctx    *t_ctx);

#endif /* SKLOG_T_H */
