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

#ifndef SKLOG_UTILS_H
#define SKLOG_UTILS_H

#include <openssl/rsa.h>

#define     SKLOG_DATA_TYPE_SIZE     sizeof(SKLOG_DATA_TYPE)

typedef struct sklog_le { //~ SKLOG_LE
    SKLOG_DATA_TYPE type;
    unsigned char *data_enc;
    unsigned int data_enc_len;
    unsigned char hash[SKLOG_HASH_CHAIN_LEN];
    unsigned char hmac[SKLOG_HMAC_LEN];
} SKLOG_LE;




SKLOG_RETURN
SKLOG_Utils_SerializeLogentry(SKLOG_LE *,
                              unsigned char **,
                              unsigned int *);
                              
SKLOG_RETURN
SKLOG_Utils_DeserializeLogentry(unsigned char *,
                                unsigned int,
                                SKLOG_LE *);

#endif /* SKLOG_UTILS_H */
