/*
 * Copyright (C) 2010 Politecnico di Torino, Italy
 *                    TORSEC group -- http://security.polito.it
 *
 * Author: Paolo Smiraglia <paolo.smiraglia@polito.it>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 */
 
#ifndef SKLOG_DEFINE_H
#define SKLOG_DEFINE_H

#define     SHA1_LEN                20 /* 160 bit */
#define     SHA256_LEN              32 /* 256 bit */
#define     BUFLEN                  1024

#define     XSMALL_BUFLEN           128
#define     SMALL_BUFLEN            256
#define     MEDIUM_BUFLEN           512
#define     LARGE_BUFLEN            1024
#define     XLARGE_BUFLEN           2048

#define     SK_HASH_CHAIN_LEN       SHA256_LEN
#define     SK_ENC_KEY_LEN          SHA256_LEN
#define     SK_HMAC_LEN             SHA256_LEN
#define     SK_AUTH_KEY_LEN         SHA256_LEN

//~ #define     SK_DATABASE_PATH        "./logs.db"
//~ #define     SK_LOGFILE_PATH         "./logs.txt"

#define     SK_VERIFY_FAILURE       2
#define     SK_VERIFY_SUCCESS       1

#define     SK_SUCCESS              0
#define     SK_FAILURE             -1

/*--------------------------------------------------------------------*/

#undef      DEBUG
#define     TRACE

#endif /* SKLOG_DEFINE_H */
