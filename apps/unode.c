#include <sklog_u.h>

#define MAX 1
#define LOGFILE_SIZE 30
#define LOGENTRY_LEN 1024

int main (void) {

	SKLOG_RETURN rv = 0;
	
	char *le1 = 0;
	unsigned int le1_len = 0;
	
	char *le2 = 0;
	unsigned int le2_len = 0;
	
	unsigned char *m0 = 0;
	unsigned int m0_len = 0;
	
	unsigned char *m1 = 0;
	unsigned int m1_len = 0;
	
	char *logs[BUF_512] = { 0x0 };
	unsigned int logs_size = 0;
	
	SKLOG_U_Ctx *u_ctx = 0;
	
	SKLOG_CONNECTION *c = 0;
	
	FILE *fp = 0;
	char event[BUF_2048+1] = { 0x0 };
	int seek = 0;
	
	char filename[BUF_512+1] = { 0x0 };
	char logfile_id[UUID_STR_LEN+1] = { 0x0 };


init_logging_session:
	
	/* initialize context */
	
	u_ctx = SKLOG_U_NewCtx();
	
	if ( u_ctx == NULL ) {
		ERROR("SKLOG_U_NewCtx() failure");
		return 1;
	}
	
	rv = SKLOG_U_InitCtx(u_ctx);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("SKLOG_U_InitCtx() failure");
		return 1;
	}
	
	/*
	 *  initialize logging session phase
	 *
	 */
	
	rv = SKLOG_U_Open_M0(u_ctx, &m0, &m0_len, &le1, &le1_len);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("SKLOG_U_Open_M0() failure");
		return 1;
	}
	
	/* setup connection */
	
	c = SKLOG_CONNECTION_New();
	
	if ( c == NULL ) {
		ERROR("SKLOG_CONNECTION_New() failure");
		rv = SKLOG_FAILURE;
		goto error;
	}
	
	rv = SKLOG_CONNECTION_Init(c, u_ctx->t_address, u_ctx->t_port,
		u_ctx->u_cert, u_ctx->u_privkey, 0, 0);
		
	if ( rv == SKLOG_FAILURE ) {
		ERROR("SKLOG_CONNECTION_Init() failure");
		goto error;
	}
	
	/* send m0 message */
	
	rv = send_m0(c, m0, m0_len);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("send_m0() failure");
		goto error;
	}
	
	/* waiting for m1 message */
	
	rv = receive_m1(c, &m1, &m1_len);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("receive_m1() failure");
		goto error;
	}
	
	/* free connection */
	
	rv = SKLOG_CONNECTION_Free(&c);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("SKLOG_CONNECTION_Free() failure");
		goto error;
	}
	
	rv = SKLOG_U_Open_M1(u_ctx, m1, m1_len, &le2, &le2_len);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("SKLOG_U_Open_M1() failure");
		return 1;
	}
	
	/*
	 *  start logging
	 *
	 */
	
	fp = fopen("rawdata.dat", "r");
	
	if ( fp == NULL ) {
		ERROR("Unable to open file rawdata.dat");
		return 1;
	}
	
	fseek(fp, seek, SEEK_SET);
	
	int eol = 0;
	
	uuid_unparse(u_ctx->logfile_id, logfile_id);
	
	snprintf(filename, BUF_512, "%s/%s.json", BIN_PREFIX, logfile_id);
	
	while ( !feof(fp) ) {
		
		fgets(event, BUF_2048, fp);
		eol = strlen(event);
		event[eol-1] = '\0';
		
		/* create log entry */
		
		rv = SKLOG_U_LogEvent(u_ctx, Undefined, event,
			strlen(event), &le1, &le1_len);
		
		if ( rv == SKLOG_SESSION_TO_RENEW ) {
			
			seek = ftell(fp);
			
			fclose(fp);
			
			SKLOG_U_Close(u_ctx, &le1, &le1_len);
			
			SKLOG_U_FlushLogfile(u_ctx, logs, &logs_size);
			
			SKLOG_U_UploadLogfile(u_ctx, filename, DUMP_MODE_JSON);
			
			
			SKLOG_U_FreeCtx(&u_ctx);
			goto init_logging_session;
		}

	}
	
	fclose(fp);
	
	SKLOG_U_Close(u_ctx, &le1, &le1_len);
	SKLOG_U_FlushLogfile(u_ctx, logs, &logs_size);
	SKLOG_U_UploadLogfile(u_ctx, filename, DUMP_MODE_JSON);
	SKLOG_U_FreeCtx(&u_ctx);
	
	/*
	 *  end application
	 *
	 */
		
	return 0;
	
error:
	return 1;
}
