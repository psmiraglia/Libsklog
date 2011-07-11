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
#define  SKLOG_DEF_LOGFILE_SIZE  10
#define  SKLOG_DEF_T_CERT_PATH  ETC_PREFIX"/libsklog/ca_cert.pem"
#define  SKLOG_DEF_U_CERT_PATH  ETC_PREFIX"/libsklog/u1_cert.pem"
#define  SKLOG_DEF_U_RSA_KEY_PATH  ETC_PREFIX"/libsklog/u1_key.pem"
#define  SKLOG_DEF_U_TIMEOUT  60

#define  SKLOG_U_DB  VAR_PREFIX"/libsklog/db/u.db"

#define  SKLOG_U_CTX_INITIALIZED  1
#define  SKLOG_U_CTX_NOT_INITIALIZED  !SKLOG_U_CTX_INITIALIZED


/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/

typedef struct sklog_u_ctx {

    int context_state;

    //~ U information
    char            u_id[HOST_NAME_MAX+1];  /* load from config file */
    unsigned int    u_id_len;
    int             u_timeout;              /* load from config file */
    X509            *u_cert;
    EVP_PKEY        *u_privkey;

    //~ T information
    X509            *t_cert;
    char            t_cert_path[512];
    char            t_address[512];
    short int       t_port;

    //~ Logging session information
    int             logfile_size;           /* load from config file */
    int             logfile_counter;
    uuid_t          logfile_id;

    unsigned char   session_key[SKLOG_SESSION_KEY_LEN];
    unsigned char   auth_key[SKLOG_AUTH_KEY_LEN];
    unsigned char   last_hash_chain[SKLOG_HASH_CHAIN_LEN];

    unsigned char   x0_hash[SHA256_LEN];

} SKLOG_U_Ctx;

/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/

SKLOG_U_Ctx
SKLOG_U_NewCtx(void);

SKLOG_RETURN
SKLOG_U_CreateLogentry(SKLOG_U_Ctx        *u_ctx,
                       SKLOG_DATA_TYPE    type,
                       char               *data,
                       unsigned int       data_len);

#endif /* SKLOG_U_H */
