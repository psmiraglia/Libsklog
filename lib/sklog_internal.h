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
**    the Free Software Foundation, either version 3 of the License, or
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

#ifndef SKLOG_INTERNAL_H
#define SKLOG_INTERNAL_H

#include "../config.h"

#include "sklog_define.h"

/**
 * SKLOG_DATA_TYPE
 *
 */
typedef enum {
    LogfileInitialization =         0x00000000,
    LogfileClosure =                0xffffffff,
    TYPE_ONE =                      0x00000001,
    TYPE_TWO =                      0x00000010,
    TYPE_THREE =                    0x00000011,
    TYPE_FOUR =                     0x00000100,
    TYPE_FIVE =                     0x00000101,
} SKLOG_DATA_TYPE;

#define     SK_LOGENTRY_TYPE_LEN    sizeof(SKLOG_DATA_TYPE)

#ifdef USE_QUOTE
typedef struct _sktpmctx SKTPMCTX;

struct _sktpmctx {
    char *srkpwd;
    char *aikpwd;
    int   aikid;
    int   pcr_to_extend;
};
#endif

/**
 * SKCTX
 *
 */
typedef struct _skctx SKCTX;

struct _skctx {
    unsigned char auth_key[SK_AUTH_KEY_LEN];
    unsigned char last_hash_chain[SK_HASH_CHAIN_LEN];
    #ifdef USE_QUOTE
    SKTPMCTX tpmctx;
    #endif
};

/**********************************************************************/
/**********************************************************************/

int
gen_enc_key(SKCTX *,unsigned char *,SKLOG_DATA_TYPE);

int /* use aes */
enc_data_des(unsigned char **,unsigned int *,unsigned char *,
             unsigned int, unsigned char *);

int
enc_data_aes256(unsigned char **,unsigned int *,unsigned char *,
                unsigned int, unsigned char *);

int /* use aes */
dec_data_des(unsigned char **,unsigned int *,unsigned char *,
             unsigned int,unsigned char *);

int
dec_data_aes256(unsigned char **,unsigned int *,unsigned char *,
                unsigned int, unsigned char *);

int
gen_hash_chain(SKCTX *,unsigned char *,unsigned char *,unsigned int,
               SKLOG_DATA_TYPE);

int
gen_hmac(SKCTX *,unsigned char *,unsigned char *);

int
renew_auth_key(SKCTX *);

int
gen_log_entry(unsigned char **,unsigned int *,SKLOG_DATA_TYPE,
              unsigned char *,unsigned int,unsigned char *,
              unsigned char *);

int
write_log_entry(unsigned char *,unsigned int);

#ifdef USE_QUOTE
int
gen_nonce(unsigned char *,SKLOG_DATA_TYPE *,unsigned char *,unsigned int,
          unsigned char *,unsigned char *);

int
load_tpm_config(SKTPMCTX *tpmctx);

int
compute_tpm_quote(SKCTX *,unsigned char *,unsigned char **,unsigned int *);
#endif

#endif /* SKLOG_INTERNAL_H */
