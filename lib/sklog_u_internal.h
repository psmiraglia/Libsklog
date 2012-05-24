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
 
#ifndef SKLOG_U_INTERNAL
#define SKLOG_U_INTERNAL

#include "sklog_commons.h"

#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <sys/time.h>
#include <uuid/uuid.h>

/*
 * U context status
 * 
 */

#define SKLOG_U_CTX_INITIALIZED 1
#define SKLOG_U_CTX_NOT_INITIALIZED !SKLOG_U_CTX_INITIALIZED

/*
 * default values for U settings
 * 
 */
 
#define  SKLOG_U_CONFIG_FILE_PATH  ETC_PREFIX"/libsklog/libsklog-u.conf"

#define SKLOG_DEF_LOGFILE_SIZE 100
#define SKLOG_DEF_T_CERT_PATH ETC_PREFIX"/libsklog/certs/ca/ca_cert.pem"
#define SKLOG_DEF_T_ADDRESS "127.0.0.1"
#define SKLOG_DEF_T_PORT 5555
#define SKLOG_DEF_U_CERT_PATH ETC_PREFIX"/libsklog/certs/u1_cert.pem"
#define SKLOG_DEF_U_RSA_KEY_PATH ETC_PREFIX"/libsklog/certs/private/u1_key.pem"
#define SKLOG_DEF_U_TIMEOUT 60
#define SKLOG_DEF_U_ID "u1.example.com"

/*
 * U context definition
 * 
 */

typedef struct sklog_u_ctx SKLOG_U_Ctx;
typedef struct sklog_u_storage_driver SKLOG_U_STORAGE_DRIVER;

struct sklog_u_ctx {

    int context_state;
    int logging_session_mgmt;

    // u-node informtion ---------------------------------------------//
    
    char            u_id[HOST_NAME_MAX+1];
    unsigned int    u_id_len;

    int             u_timeout;
    unsigned long	u_expiration;

    X509            *u_cert;
    char            u_cert_file_path[MAX_FILE_PATH_LEN];
    
    EVP_PKEY        *u_privkey;
    char            u_privkey_file_path[MAX_FILE_PATH_LEN];

    // t-node information --------------------------------------------//
    
    X509            *t_cert;
    char            t_cert_file_path[MAX_FILE_PATH_LEN];

    char            t_address[512];
    short int       t_port;

    // logging session information -----------------------------------//
    
    int             logfile_size;
    int             logfile_counter;
    uuid_t          logfile_id;

    unsigned char   session_key[SKLOG_SESSION_KEY_LEN];
    unsigned char   auth_key[SKLOG_AUTH_KEY_LEN];
    unsigned char   last_hash_chain[SKLOG_HASH_CHAIN_LEN];

    unsigned char   x0_hash[SHA256_LEN];

    // log-entries storage driver ------------------------------------//
    
    SKLOG_U_STORAGE_DRIVER *lsdriver;

};

struct sklog_u_storage_driver {

    SKLOG_RETURN (*store_logentry) (uuid_t, SKLOG_DATA_TYPE, 
		unsigned char *, unsigned int, unsigned char *,
		unsigned char *);
		
    SKLOG_RETURN (*flush_logfile) (uuid_t, unsigned long,
		SKLOG_CONNECTION *);
		
    SKLOG_RETURN (*init_logfile) (uuid_t, unsigned long);
    
    SKLOG_RETURN (*flush_logfile_v2) (char *logfile_id, char *logs[],
		unsigned int *logs_size);
};

/*
 * internal function prototypes
 * 
 */

SKLOG_RETURN gen_enc_key(SKLOG_U_Ctx *ctx, SKLOG_DATA_TYPE type,
	unsigned char *enc_key);

SKLOG_RETURN gen_hash_chain(SKLOG_U_Ctx *ctx, unsigned char *data_enc,
	unsigned int data_enc_size, SKLOG_DATA_TYPE type, unsigned char *y);

SKLOG_RETURN gen_hmac(SKLOG_U_Ctx *ctx, unsigned char *hash_chain,
	unsigned char *hmac);

SKLOG_RETURN renew_auth_key(SKLOG_U_Ctx *ctx);

SKLOG_RETURN create_logentry(SKLOG_U_Ctx *u_ctx, SKLOG_DATA_TYPE type,
	unsigned char *data, unsigned int data_len, int req_blob, 
	char **blob, unsigned int *blob_len);

SKLOG_RETURN parse_u_config_file(char *t_cert_path, char *t_address, 
	int *t_port, char *u_cert_path, char *u_id, char *u_privkey_path,
	unsigned int *u_timeout, unsigned int *logfile_max_size);

SKLOG_RETURN gen_x0(SKLOG_U_Ctx *u_ctx, SKLOG_PROTOCOL_STEP p,
	unsigned long d, unsigned char **x0, unsigned int *x0_len);

SKLOG_RETURN gen_e_k0(SKLOG_U_Ctx *u_ctx, unsigned char *x0,
	unsigned int x0_len, unsigned char *x0_sign,
	unsigned int x0_sign_len, unsigned char **e_k0,
	unsigned int *e_k0_len);

SKLOG_RETURN gen_m0(SKLOG_U_Ctx *u_ctx, SKLOG_PROTOCOL_STEP p,
	unsigned char *pke_t_k0, unsigned int pke_t_k0_len,
	unsigned char *e_k0, unsigned int e_k0_len, unsigned char **m0,
	unsigned int *m0_len);

SKLOG_RETURN gen_d0(SKLOG_U_Ctx *u_ctx, unsigned long d,
	unsigned long d_timeout, unsigned char *m0, unsigned int m0_len,
	unsigned char **d0, unsigned int *d0_len);

SKLOG_RETURN send_m0(SKLOG_CONNECTION *c, unsigned char *m0, 
	unsigned int m0_len);

SKLOG_RETURN receive_m1(SKLOG_CONNECTION *c, unsigned char **m1, 
	unsigned int *m1_len);

SKLOG_RETURN parse_m1(unsigned char *m1, unsigned int m1_len, 
	SKLOG_PROTOCOL_STEP *p, unsigned char *t_id,
	unsigned char **pke_u_k1, unsigned int *pke_u_k1_len, 
	unsigned char **e_k1, unsigned int *e_k1_len);

SKLOG_RETURN parse_e_k1_content(unsigned char *in, unsigned int in_len,
	unsigned char **x1, unsigned int *x1_len, unsigned char **x1_sign,
	unsigned int *x1_sign_len);

SKLOG_RETURN verify_m1(SKLOG_U_Ctx *ctx, unsigned char *m1, 
	unsigned int m1_len);

SKLOG_RETURN verify_timeout_expiration(unsigned long d_timeout);

SKLOG_RETURN initialize_context(SKLOG_U_Ctx *u_ctx);

SKLOG_RETURN initialize_logging_session(SKLOG_U_Ctx *u_ctx,
	int req_blob, char **le1, unsigned int *le1_len, char **le2,
	unsigned int *le2_len);

SKLOG_RETURN flush_logfile_init(SKLOG_CONNECTION *c);

SKLOG_RETURN flush_logfile_terminate(SKLOG_CONNECTION *c);

SKLOG_RETURN flush_logfile_execute(SKLOG_U_Ctx *u_ctx,
	unsigned long now);
	
SKLOG_RETURN generate_m0_message(SKLOG_U_Ctx *u_ctx, unsigned char **msg,
	unsigned int *msg_len, char **le, unsigned int *le_len);
	
SKLOG_RETURN verify_m1_message(SKLOG_U_Ctx *u_ctx, unsigned char *m1,
	unsigned int m1_len, char **le,	unsigned int *le_len);

#endif /* SKLOG_U_INTERNAL */
