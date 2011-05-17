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

#ifndef SKLOG_H
#define SKLOG_H

#include "../config.h"

#include "sklog_define.h"
#include "sklog_internal.h"

typedef struct _sklogentry SKLogEntry;

struct _sklogentry {
    unsigned char type[SK_LOGENTRY_TYPE_LEN];
    unsigned char *data_enc;
    unsigned int data_enc_len;
    unsigned char hash[SK_HASH_CHAIN_LEN];
    unsigned char hmac[SK_HMAC_LEN];

    #ifdef USE_QUOTE
    unsigned char *quote;
    unsigned int quote_size;
    #endif
};

int SKLOG_InitLogEntry(SKLogEntry*);

int SKLOG_ResetLogEntry(SKLogEntry*);

int SKLOG_LogEntryToBlob(unsigned char**,unsigned int*,SKLogEntry*);

int SKLOG_InitCtx(SKCTX *);

int SKLOG_SetAuthKeyZero(SKCTX *,unsigned char *);

//~ int SKLOG_Open(SKCTX *,SKLogEntry*);

//~ int SKLOG_Close(SKCTX *,SKLogEntry*);

int SKLOG_Write(SKCTX *,const char *,int,SKLOG_DATA_TYPE,SKLogEntry*);

#endif /* SKLOG_H */
