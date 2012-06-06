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

#ifndef SKLOG_MISC
#define SKLOG_MISC

#include "../sklog_commons.h"
#include "../sklog_internal.h"

#include <uuid/uuid.h>

#define LOGFILE_PATH VAR_PREFIX"/log/libsklog"

/*--------------------------------------------------------------------*/
/*                      U driver callbacks                            */
/*--------------------------------------------------------------------*/

SKLOG_RETURN sklog_misc_u_store_logentry_v2(char *logfile_id,
	char *logentry);
	
SKLOG_RETURN sklog_misc_u_flush_logfile_v2(char *logfile_id,
	char *logs[], unsigned int *logs_size);
		
SKLOG_RETURN sklog_misc_u_init_logfile_v2(char *logfile_id,
	unsigned long t);

SKLOG_RETURN sklog_misc_u_close_logfile_v2(char *logfile_id,
	unsigned long t);
	
SKLOG_RETURN sklog_misc_u_dump_raw(char *logfile_id,
	const char *filename);
	
SKLOG_RETURN sklog_misc_u_dump_json(char *logfile_id,
	const char *filename);
	
SKLOG_RETURN sklog_misc_u_dump_soap(char *logfile_id,
	const char *filename);

/* ------------ */
/*  deprecated  */
/* ------------ */
	
SKLOG_RETURN sklog_misc_u_store_logentry(uuid_t logfile_id,
	SKLOG_DATA_TYPE	type, unsigned char *data, unsigned int	data_len,
	unsigned char *hash, unsigned char *hmac);

SKLOG_RETURN sklog_misc_u_flush_logfile(uuid_t logfile_id,
	unsigned long now, SKLOG_CONNECTION *c);

SKLOG_RETURN sklog_misc_u_init_logfile(uuid_t logfile_id,
	unsigned long t);
	
/*--------------------------------------------------------------------*/
/*                      T driver callbacks                            */
/*--------------------------------------------------------------------*/

#define TAB_M0MSG_COL_ID 0
#define TAB_M0MSG_COL_ADDRESS 1
#define TAB_M0MSG_COL_LOGFILEID 2
#define	TAB_M0MSG_COL_M0MSG 3

#define TAB_AUTHKEY_COL_ID 0
#define TAB_AUTHKEY_COL_IP 1
#define TAB_AUTHKEY_COL_LOGFILEID 2
#define TAB_AUTHKEY_COL_AUTHKEY 3

#define TAB_LOGENTRY_COL_ID 0
#define TAB_LOGENTRY_COL_LOGFILEID 1
#define TAB_LOGENTRY_COL_TYPE 2
#define TAB_LOGENTRY_COL_DATA 3
#define TAB_LOGENTRY_COL_HASH 4
#define TAB_LOGENTRY_COL_HMAC 5

#define	SKLOG_T_DB VAR_PREFIX"/libsklog/db/t.db"

SKLOG_RETURN sklog_misc_t_store_authkey_v2(char *address,
	char *logfile_id, unsigned char *authkey);

SKLOG_RETURN sklog_misc_t_store_m0_msg_v2(char *address,
	char *logfile_id, unsigned char *m0, unsigned int m0_len);
	
SKLOG_RETURN sklog_misc_t_retrieve_logfiles_v2(char *uuid_list[],
	unsigned int *uuid_list_size);

SKLOG_RETURN sklog_misc_t_verify_logfile_v2(char *logfile_id);

SKLOG_RETURN
sklog_misc_t_store_logentry_v2 (char *logfile_id, char *logentry,
								unsigned int logentry_len);

/* ------------ */
/*  deprecated  */
/* ------------ */

SKLOG_RETURN sklog_misc_t_store_authkey(char *u_ip, uuid_t logfile_id,
	unsigned char *authkey);
	
SKLOG_RETURN sklog_misc_t_store_m0_msg(char *u_ip, uuid_t	logfile_id,
	unsigned char *m0, unsigned int	m0_len);
	
SKLOG_RETURN sklog_misc_t_store_logentry(unsigned char *blob,
	unsigned int blob_len);

SKLOG_RETURN sklog_misc_t_retrieve_logfiles(unsigned char	**uuid_list,
	unsigned int *uuid_list_len);
	
SKLOG_RETURN sklog_misc_t_verify_logfile(unsigned char *uuid);

#endif /* SKLOG_MISC */
