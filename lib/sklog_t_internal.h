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

#ifndef SKLOG_T_INTERNAL
#define SKLOG_T_INTERNAL

#include "sklog_commons.h"

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <sys/time.h>

#include <uuid/uuid.h>

/*
 * default values for T settings
 * 
 */
 
#define SKLOG_T_MAX_THREADS     1

#define SKLOG_T_CONFIG_FILE_PATH  ETC_PREFIX"/libsklog/libsklog-t.conf"

#define SKLOG_DEF_T_CERT_PATH ETC_PREFIX"/libsklog/certs/ca/ca_cert.pem"
#define SKLOG_DEF_T_RSA_KEY_PASSPHRASE "123456"
#define SKLOG_DEF_T_RSA_KEY_PATH ETC_PREFIX"/libsklog/certs/private/ca_key.pem"
#define SKLOG_DEF_T_ADDRESS "127.0.0.1"
#define SKLOG_DEF_T_ID "t.example.com"
#define SKLOG_DEF_T_PORT 5555

/*
 * T context structure definition
 * 
 */
 
typedef struct sklog_t_ctx SKLOG_T_Ctx;
typedef struct sklog_t_storage_driver SKLOG_T_STORAGE_DRIVER;

struct sklog_t_ctx {

	char		t_id[HOST_NAME_MAX+1];
	int			t_id_len;
	
	char		t_address[HOST_NAME_MAX+1];
	short int	t_port;
	
	X509		*t_cert;
	char		t_cert_file_path[MAX_FILE_PATH_LEN];
	
	EVP_PKEY	*t_privkey;
	char		t_privkey_file_path[MAX_FILE_PATH_LEN];
	
	SKLOG_T_STORAGE_DRIVER	*lsdriver;
};

struct sklog_t_storage_driver {
    SKLOG_RETURN (*store_authkey) (char*,uuid_t,unsigned char*);
    SKLOG_RETURN (*store_m0_msg) (char*,uuid_t,unsigned char*,unsigned int);
    SKLOG_RETURN (*store_logentry) (unsigned char*,unsigned int);
    SKLOG_RETURN (*retrieve_logfiles) (unsigned char **,unsigned int *);
    SKLOG_RETURN (*retrieve_logfiles_2) (char *uuid_list[],unsigned int *);
    SKLOG_RETURN (*verify_logfile) (unsigned char *);
};

/*
 * internal function prototype
 * 
 */

SKLOG_RETURN parse_t_config_file(char *t_cert_path, char *t_privkey_path,
	char *t_privkey_passphrase, char *t_id, char *t_address,
	int *t_port);

SKLOG_RETURN parse_m0(SKLOG_T_Ctx *t_ctx, unsigned char *m0,
	unsigned int m0_len, SKLOG_PROTOCOL_STEP *p, uuid_t *logfile_id,
	unsigned char **pke_t_k0, unsigned int *pke_t_k0_len,
	unsigned char **e_k0, unsigned int *e_k0_len);

SKLOG_RETURN verify_m0_signature(X509 *u_cert, unsigned char *x0_sign,
	size_t x0_sign_len, unsigned char *x0, unsigned int x0_len);

SKLOG_RETURN verify_m0_certificate(X509 *u_cert);

SKLOG_RETURN parse_e_k0_content(unsigned char *in, unsigned int in_len,
	unsigned char **x0, unsigned int *x0_len, unsigned char **x0_sign,
	unsigned int *x0_sign_len);

SKLOG_RETURN parse_x0( unsigned char *x0, unsigned int x0_len,
	X509 **u_cert, unsigned char *auth_key);

SKLOG_RETURN gen_x1(SKLOG_PROTOCOL_STEP *p, unsigned char *x0,
	unsigned int x0_len, unsigned char **x1, unsigned int *x1_len);

SKLOG_RETURN gen_e_k1(SKLOG_T_Ctx *t_ctx, unsigned char *k1,
	unsigned char *x1, unsigned int x1_len, unsigned char *x1_sign,
	unsigned int x1_sign_len, unsigned char **e_k1,
	unsigned int *e_k1_len);      

SKLOG_RETURN gen_m1(SKLOG_T_Ctx *t_ctx, SKLOG_PROTOCOL_STEP p,
	unsigned char *pke_u_k1, unsigned int pke_u_k1_len, 
	unsigned char *e_k1, unsigned int e_k1_len, unsigned char **m1,
	unsigned int *m1_len);      

SKLOG_RETURN send_m1(SKLOG_T_Ctx *t_ctx, SKLOG_CONNECTION *conn,
	unsigned char *m1, unsigned int m1_len);


#endif /* SKLOG_T_INTERNAL */
