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

#ifndef SKLOG_SQLITE
#define SKLOG_SQLITE

#ifdef USE_SQLITE

#include "../sklog_commons.h"
#include "../sklog_internal.h"

#include <sqlite3.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <sys/time.h>
#include <uuid/uuid.h>

/*--------------------------------------------------------------------*/
/*                             u                                      */
/*--------------------------------------------------------------------*/

#define  SKLOG_U_DB  VAR_PREFIX"/libsklog/db/u.db"
#define  SKLOG_T_DB  VAR_PREFIX"/libsklog/db/t.db"

SKLOG_RETURN
sklog_sqlite_u_store_logentry(uuid_t             logfile_id,
                              SKLOG_DATA_TYPE    type,
                              unsigned char      *data,
                              unsigned int       data_len,
                              unsigned char      *hash,
                              unsigned char      *hmac);

SKLOG_RETURN
sklog_sqlite_u_flush_logfile(uuid_t    logfile_id,
                             struct timeval *now,
                             SSL       *ssl);

SKLOG_RETURN
sklog_sqlite_u_init_logfile(uuid_t            logfile_id,
                            struct timeval    *t);

/*--------------------------------------------------------------------*/
/*                             t                                      */
/*--------------------------------------------------------------------*/

SKLOG_RETURN
sklog_sqlite_t_store_authkey(char             *u_ip,
                             uuid_t           logfile_id,
                             unsigned char    *authkey);

SKLOG_RETURN
sklog_sqlite_t_store_logentry(unsigned char    *blob,
                              unsigned int     blob_len);
#endif /* USE_SQLITE */

#endif /* SKLOG_SQLITE */
