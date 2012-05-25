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

#include "sklog_misc.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>


/*--------------------------------------------------------------------*/
/*                      U driver callbacks                            */
/*--------------------------------------------------------------------*/

/*
 * deprecated
 * 
 */
 
SKLOG_RETURN sklog_misc_u_store_logentry(uuid_t logfile_id,
	SKLOG_DATA_TYPE	type, unsigned char *data, unsigned int	data_len,
	unsigned char *hash, unsigned char *hmac)
{
	NOTIFY("%s", MSG_NOT_IMPLEMENTED);
	return SKLOG_SUCCESS;
}

/*
 * ok
 */
 
SKLOG_RETURN sklog_misc_u_store_logentry_v2(char *logfile_id,
	char *logentry)
{
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	int rv = 0;
	
	FILE *fp = 0;
	char filename[BUF_512+1] = { 0x0 };
	
	/* chech input parameters */
	
	if ( logfile_id == NULL || logentry == NULL ) {
		ERROR("%s", MSG_BAD_INPUT_PARAMS);
		return SKLOG_FAILURE;
	}
	
	/* open logfile */
	
	rv = snprintf(filename, BUF_512, "%s/%s.log", LOGFILE_PATH,
		logfile_id);
		
	if ( rv < 0 ) {
		ERROR("snprintf() failure");
		return SKLOG_FAILURE;
	}
	
	fp = fopen(filename, "a");
	
	if ( fp == NULL ) {
		ERROR("Unable to open file %s", filename);
		return SKLOG_FAILURE;
	}
	
	/* write logentry */
	
	rv = fprintf(fp, "%s\n", logentry);
	
	if ( rv < 0 ) {
		ERROR("fprintf() failure");
		return SKLOG_FAILURE;
	}
	
	/* close file */
	
	fclose(fp);
	
	return SKLOG_SUCCESS;
}

/*
 * deprecated
 * 
 */

SKLOG_RETURN sklog_misc_u_flush_logfile(uuid_t logfile_id,
	unsigned long now, SKLOG_CONNECTION *c)
{
	NOTIFY("%s", MSG_NOT_IMPLEMENTED);
	return SKLOG_SUCCESS;
}

/*
 * ok
 */
 	
SKLOG_RETURN sklog_misc_u_flush_logfile_v2(char *logfile_id,
	char *logs[], unsigned int *logs_size)
{
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	int rv = 0;
	
	FILE *fp = 0;
	char filename[BUF_512+1] = { 0x0 };
	
	char buf[BUF_8192+1] = { 0x0 };
	int bufl = 0;
	
	int counter = 0;
	
	/* chech input parameters */
	
	if ( logfile_id == NULL ) {
		ERROR("%s", MSG_BAD_INPUT_PARAMS);
		return SKLOG_FAILURE;
	}
	
	/* open logfile */
	
	rv = snprintf(filename, BUF_512, "%s/%s.log", LOGFILE_PATH,
		logfile_id);
		
	if ( rv < 0 ) {
		ERROR("snprintf() failure");
		return SKLOG_FAILURE;
	}
	
	fp = fopen(filename, "r");
	
	if ( fp == NULL ) {
		ERROR("Unable to open file %s", filename);
		return SKLOG_FAILURE;
	}
	
	/* read file */
	
	while ( !feof(fp) ) {
		
		/**
		 * NOTE
		 * 
		 * fgets() reads in at most one less than size characters from
		 * stream and stores them into the buffer pointed to by s.
		 * Reading stops after an EOF or a newline. If a newline is
		 * read, it is stored into the  buffer. A terminating null byte
		 * ('\0') is stored after the last character in the buffer.
		 * 
		 */
		 
		if ( fgets(buf, BUF_8192, fp) != NULL ) {
		
			bufl = strlen(buf);
			
			logs[counter] = calloc(bufl+1, sizeof(char));
			
			if ( logs[counter] == NULL ) {
				ERROR("calloc() failure");
				fclose(fp);
				return SKLOG_FAILURE;
			}
			
			memcpy(logs[counter], buf, bufl);
			
			memset(buf, 0, BUF_8192);
			
			counter++;
		}
	}
	
	*logs_size = counter;
	
	fclose(fp);
	
	return SKLOG_SUCCESS;
}

/*
 * deprecated
 * 
 */

SKLOG_RETURN sklog_misc_u_init_logfile(uuid_t logfile_id,
	unsigned long t)
{
	NOTIFY("%s", MSG_NOT_IMPLEMENTED);
	return SKLOG_SUCCESS;
}

/*
 * ok
 */
	
SKLOG_RETURN sklog_misc_u_init_logfile_v2(char *logfile_id,
	unsigned long t)
{
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	int rv = 0;
	
	FILE *fp = 0;
	char filename[BUF_512+1] = { 0x0 };
	
	char timestamp[BUF_512+1] = { 0x0 };
	
	/* chech input parameters */
	
	if ( logfile_id == NULL ) {
		ERROR("%s", MSG_BAD_INPUT_PARAMS);
		return SKLOG_FAILURE;
	}
	
	/* ascii-ze timestamp */
	
	rv = time_usec2ascii(timestamp, t);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("time_usec2ascii() failure");
		return SKLOG_FAILURE;
	}
	
	/* open logfile */
	
	rv = snprintf(filename, BUF_512, "%s/%s.log", LOGFILE_PATH,
		logfile_id);
		
	if ( rv < 0 ) {
		ERROR("snprintf() failure");
		return SKLOG_FAILURE;
	}
	
	fp = fopen(filename, "w+");
	
	if ( fp == NULL ) {
		ERROR("Unable to create file %s", filename);
		return SKLOG_FAILURE;
	}
	
	/* write init metadata */
	
	fprintf(fp, "# LOGFILE_ID: %s\n", logfile_id);
	fprintf(fp, "# OPENED: %s\n\n", timestamp);
	
	fclose(fp);
	
	return SKLOG_SUCCESS;
}

SKLOG_RETURN sklog_misc_u_close_logfile_v2(char *logfile_id,
	unsigned long t)
{
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	int rv = 0;
	
	FILE *fp = 0;
	char filename[BUF_512+1] = { 0x0 };
	
	char timestamp[BUF_512+1] = { 0x0 };
	
	/* chech input parameters */
	
	if ( logfile_id == NULL ) {
		ERROR("%s", MSG_BAD_INPUT_PARAMS);
		return SKLOG_FAILURE;
	}
	
	/* ascii-ze timestamp */
	
	rv = time_usec2ascii(timestamp, t);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("time_usec2ascii() failure");
		return SKLOG_FAILURE;
	}
	
	/* open logfile */
	
	rv = snprintf(filename, BUF_512, "%s/%s.log", LOGFILE_PATH,
		logfile_id);
		
	if ( rv < 0 ) {
		ERROR("snprintf() failure");
		return SKLOG_FAILURE;
	}
	
	fp = fopen(filename, "a");
	
	if ( fp == NULL ) {
		ERROR("Unable to open file %s", filename);
		return SKLOG_FAILURE;
	}
	
	/* write close metadata */
	
	fprintf(fp, "\n# CLOSED: %s", timestamp);
	
	fclose(fp);
	
	return SKLOG_SUCCESS;
}

/*
 * 
 */
 
SKLOG_RETURN sklog_misc_u_dump_raw(char *logfile_id,
	const char *filename)
{
	return SKLOG_SUCCESS;
}

/*
 * 
 */
 
SKLOG_RETURN sklog_misc_u_dump_json(char *logfile_id,
	const char *filename)
{
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	int rv = SKLOG_SUCCESS;
	
	FILE *in = 0;
	char fin[BUF_512+1] = { 0x0 };
	
	FILE *out = 0;
	
	char line[BUF_8192+1] = { 0x0 };
	int eol = 0;
	
	/* check input parameters */
	
	if ( logfile_id == NULL || filename == NULL ) {
		ERROR(MSG_BAD_INPUT_PARAMS);
		return SKLOG_FAILURE;
	}
	
	/* open files */
	
	rv = snprintf(fin, BUF_512, "%s/%s.log", LOGFILE_PATH, logfile_id);
	
	if ( rv < 0 ) {
		ERROR("snprintf() failure");
		return SKLOG_FAILURE;
	}
	
	in = fopen(fin, "r");
	
	if ( in == NULL ) {
		ERROR("Unable to open file %s", fin);
		return SKLOG_FAILURE;
	}
	
	out = fopen(filename, "w+");
	
	if ( out == NULL ) {
		ERROR("Unable to open file %s", filename);
		return SKLOG_FAILURE;
	}
	
	/* read */
	
	fprintf(out, "{\"session\":\"%s\",\"logs\":[", logfile_id);
	
	while ( !feof(in) ) {
		
		fgets(line, BUF_8192, in);
		
		if ( line[0] == '#' || line[0] == '\n' || line[0] == '\0' ) {
			memset(line, 0, BUF_8192);
			continue;
		}

		/* remove newline */
		
		eol = strlen(line);
		line[eol-1] = '\0';
		
		fprintf(out, "%s,", line);
		
		memset(line, 0, BUF_8192);
	}
	
	fprintf(out, "{}]}\n");
	
	fclose(in);
	fclose(out);
	
	return SKLOG_SUCCESS;
}	

/*
 * 
 */
 	
SKLOG_RETURN sklog_misc_u_dump_soap(char *logfile_id,
	const char *filename)
{
	return SKLOG_SUCCESS;
}

/*--------------------------------------------------------------------*/
/*                      T driver callbacks                            */
/*--------------------------------------------------------------------*/

static int sql_callback(void *NotUsed, int argc, char **argv,
	char **azColName)
{
	int i = 0;
	for ( i = 0 ; i < argc ; i++ )
		ERROR("%s = %s", azColName[i], argv[i] ? argv[i] : "NULL");
	return 0;
}

/*
 * deprecated
 * 
 */
 
SKLOG_RETURN sklog_misc_t_store_authkey(char *u_ip, uuid_t logfile_id,
	unsigned char *authkey)
{
	
	/**
	 * 
	 * strores authkeys in database
	 * 
	 * | key | ip_address | logfile_id | {authkey} |
	 * 
	 */
	
	return SKLOG_SUCCESS;
}

/*
 * ok
 * 
 */
 
SKLOG_RETURN sklog_misc_t_store_authkey_v2(char *address,
	char *logfile_id, unsigned char *authkey)
{
	
	/**
	 * 
	 * strores authkeys in database
	 * 
	 * | key | ip_address | logfile_id | {authkey} |
	 * 
	 */
	 
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	int rv = SKLOG_SUCCESS;
	
	sqlite3 *db = 0;
	char *sql_err_msg = 0;
	char query[BUF_4096+1] = { 0x0 };
	
	char *key = 0;
	
	/* check input parameters */
	
	if ( address == NULL || logfile_id == NULL || authkey == NULL ) {
		ERROR("%s", MSG_BAD_INPUT_PARAMS);
		return SKLOG_FAILURE;
	}
	
	/* compose query */
	
	rv = b64_enc(authkey, SKLOG_AUTH_KEY_LEN, &key);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("b64_enc() failure");
		return SKLOG_FAILURE;
	}
	
	snprintf(query, BUF_4096,
		"insert into AUTHKEY (u_ip,f_uuid,authkey) values ('%s','%s','%s')",
		address, logfile_id, key);
		
	free(key);
		
	/* exec query */
	
	sqlite3_open(SKLOG_T_DB, &db);
	
	if ( db == NULL ) {
		ERROR("sqlite3_open() failure: %s", sqlite3_errmsg(db));
		sqlite3_close(db);
		return SKLOG_FAILURE;
	}
	
	rv = sqlite3_exec(db, query, sql_callback, 0, &sql_err_msg);

	if ( rv != SQLITE_OK ) {
		ERROR("sqlite3_exec() failure: %s", sql_err_msg);
		sqlite3_free(sql_err_msg);
		sqlite3_close(db);
		return SKLOG_FAILURE;
	}

	sqlite3_free(sql_err_msg);
	sqlite3_close(db);
	 
	return SKLOG_SUCCESS;
}

/*
 * deprecated
 * 
 */
 
SKLOG_RETURN sklog_misc_t_store_m0_msg(char *u_ip, uuid_t	logfile_id,
	unsigned char *m0, unsigned int	m0_len)
{
	/**
	 * 
	 * strores m0 messages in database
	 * 
	 * | key | ip_address | logfile_id | m0_message |
	 * 
	 */
	 
	return SKLOG_SUCCESS;
}
	
/*
 * ok
 * 
 */
 
SKLOG_RETURN sklog_misc_t_store_m0_msg_v2(char *address,
	char *logfile_id, unsigned char *m0, unsigned int m0_len)
{
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	int rv = SKLOG_SUCCESS;
	
	sqlite3 *db = 0;
	char *sql_err_msg = 0;
	
	char query[BUF_8192+1] = { 0x0 };
	
	char *m0b64 = 0;
	
	/* chech input parameters */
	
	if ( address == NULL || logfile_id == NULL || m0 == NULL ) {
		ERROR("%s", MSG_BAD_INPUT_PARAMS);
		return SKLOG_FAILURE;
	}
	
	/* compose query */
	
	rv = b64_enc(m0, m0_len, &m0b64);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("b64_enc() failure");
		return SKLOG_FAILURE;
	}
	
	snprintf(query, BUF_8192,
		"insert into M0MSG (u_ip,f_uuid,m0_msg) values ('%s','%s','%s')",
		address, logfile_id, m0b64);
	
	/* exec query */
	
	sqlite3_open(SKLOG_T_DB, &db);
	
	if ( db == NULL ) {
		ERROR("sqlite3_open() failure: %s", sqlite3_errmsg(db));
		sqlite3_close(db);
		return SKLOG_FAILURE;
	}
	
	rv = sqlite3_exec(db, query, sql_callback, 0, &sql_err_msg);

	if ( rv != SQLITE_OK ) {
		ERROR("sqlite3_exec() failure: %s", sql_err_msg);
		sqlite3_free(sql_err_msg);
		sqlite3_close(db);
		return SKLOG_FAILURE;
	}

	sqlite3_free(sql_err_msg);
	sqlite3_close(db);
	
	return SKLOG_SUCCESS;
}	

/*
 * deprecated
 * 
 */
 	
SKLOG_RETURN sklog_misc_t_store_logentry(unsigned char *blob,
	unsigned int blob_len)
{
	/**
	 * 
	 * probably will be deprecate
	 * 
	 */
	 
	return SKLOG_SUCCESS;
}

/*
 * deprecated
 * 
 */
 
SKLOG_RETURN sklog_misc_t_retrieve_logfiles(unsigned char	**uuid_list,
	unsigned int *uuid_list_len)
{
	/**
	 * 
	 * probably will be deprecate
	 * 
	 */
	 
	return SKLOG_SUCCESS;
}

/*
 * ok
 * 
 */
 	
SKLOG_RETURN sklog_misc_t_retrieve_logfiles_v2(char *uuid_list[],
	unsigned int *uuid_list_size)
{
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	int rv = SKLOG_SUCCESS;
	
	sqlite3 *db = 0;
	sqlite3_stmt *stmt = 0;
	
	char query[BUF_512+1] = { 0x0 };
	
	char *sql_err_msg = 0;
	int sql_step = 0;
	
	int one_step_forward = 1;
	int counter = 0;
	
	const unsigned char *text = 0;
	int bytes = 0;
	
	/* compose query */
	
	snprintf(query, BUF_512, "select * from AUTHKEY");
	
	/* exec query */
	
	
	sqlite3_open(SKLOG_T_DB, &db);
	
	if ( db == NULL ) {
		ERROR("sqlite3_open() failure: %s", sqlite3_errmsg(db));
		sqlite3_close(db);
		return SKLOG_FAILURE;
	}
	
	rv = sqlite3_prepare_v2(db, query, strlen(query)+1, &stmt, NULL);
	
	if ( rv != SQLITE_OK ) {
		ERROR("sqlite3_prepare_v2() failure: %s", sqlite3_errmsg(db));
		return SKLOG_FAILURE;
	}
	
	/* flush */
	
	while ( one_step_forward > 0 ) {
		
		sql_step = sqlite3_step(stmt);
		
		switch ( sql_step ) {
			
			case SQLITE_ROW:
				text = sqlite3_column_text(stmt,
					TAB_M0MSG_COL_LOGFILEID);
				bytes = sqlite3_column_bytes(stmt,
					TAB_M0MSG_COL_LOGFILEID);
				
				uuid_list[counter] = calloc(bytes+1, sizeof(char));
				memset(uuid_list[counter], 0, bytes+1);
				memcpy(uuid_list[counter], text, bytes);
				counter++;
				break;
				
			case SQLITE_DONE:
				one_step_forward = 0;
				break;
				
			default:
				ERROR("sqlite3_step() failure: %s", sqlite3_errmsg(db));
				one_step_forward = -1;
				break;
		} 
	}
	
	if ( one_step_forward < 0 ) {
		sqlite3_close(db);
		sqlite3_free(sql_err_msg);
		return SKLOG_FAILURE;
	}
	
	*uuid_list_size = counter;
	
	sqlite3_close(db);
	sqlite3_free(sql_err_msg);
		
	return SKLOG_SUCCESS;
}

/*
 * deprecated
 * 
 */
 	
SKLOG_RETURN sklog_misc_t_verify_logfile(unsigned char *uuid)
{
	return SKLOG_SUCCESS;
}

/*
 * ok
 * 
 */

SKLOG_RETURN sklog_misc_t_verify_logfile_v2(char *logfile_id)
{
	#ifdef DO_TARCE
	DEBUG
	#endif
	
	TO_IMPLEMENT;
	
	return SKLOG_SUCCESS;
}
