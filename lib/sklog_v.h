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

#ifndef SKLOG_V_H
#define SKLOG_V_H

#include "sklog_commons.h"

#include <openssl/x509.h>

#define  SKLOG_V_CONFIG_FILE_PATH  ETC_PREFIX"/libsklog/libsklog-v.conf"
#define  SKLOG_DEF_V_CERT_PATH     ETC_PREFIX"/libsklog/certs/v_cert.pem"
#define  SKLOG_DEF_V_RSA_KEY_PATH  ETC_PREFIX"/libsklog/certs/private/v_key.pem"
#define  SKLOG_DEF_T_ADDRESS       "127.0.0.1"
#define  SKLOG_DEF_T_PORT          5555
#define  SKLOG_DEF_T_CERT_PATH     ETC_PREFIX"/libsklog/certs/ca/ca_cert.pem"

#define  SKLOG_V_CTX_INITIALIZED  1
#define  SKLOG_V_CTX_NOT_INITIALIZED  !SKLOG_V_CTX_INITIALIZED

/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/

typedef struct sklog_v_ctx SKLOG_V_Ctx;

struct sklog_v_ctx {
    
    int context_state;

    X509            *v_cert;
    EVP_PKEY        *v_privkey;
    char            t_cert_path[512];
    char            t_address[512];
    short int       t_port;
    
};

/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/

SKLOG_V_Ctx*
SKLOG_V_NewCtx(void);

SKLOG_RETURN
SKLOG_V_InitCtx(SKLOG_V_Ctx *ctx);

SKLOG_RETURN
SKLOG_V_FreeCtx(SKLOG_V_Ctx **ctx);

SKLOG_RETURN
SKLOG_V_RetrieveLogFiles(SKLOG_V_Ctx *v_ctx);

#endif /* SKLOG_V_H */
