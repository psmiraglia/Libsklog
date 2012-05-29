#include <stdio.h>
#include <readline/readline.h>
#include <readline/history.h>

#include <sklog_v.h>

#define RBUF_LEN 1024

void help(void);
void prompt(char *cmd);
void print_result(SKLOG_V_Ctx *vctx);

void show_menu(void);

int main (int argc, char **argv) {

	int rv = SKLOG_SUCCESS;
	char cmd[BUF_512+1] = { 0x0 };
	char *line = 0;
	int id = 0;

    SKLOG_V_Ctx *vctx = 0;
    
	/* create and initialize V context */
	
    vctx = SKLOG_V_NewCtx();
    
    if ( vctx == NULL ) {
		ERROR("SKLOG_V_NewCtx() failure");
		goto terminate;
	}

    rv = SKLOG_V_InitCtx(vctx);
    
    if ( rv == SKLOG_FAILURE ) {
		ERROR("SKLOG_V_InitCtx() failure");
		goto terminate;
	}

	/*
	 * show manifest
	 * 
	 */
	 
    fprintf(stdout,
		"Welcome to Libsklog verifier shell!\n"
		"Press H to visualize the available commands or X to quit.\n");

	/*
	 * run
	 * 
	 */
	 
    while ( 1 ) {

		/* show prompt and read commands */
		 
        prompt(cmd);
        
        /* parse command */
        
        switch ( cmd[0] ) {
            case 'H':
            case 'h':
                help();
                break;
                
            case 'S':
            case 's':

				/*
				 * Retrieve
				 * 
				 */
				 
                rv = SKLOG_V_RetrieveLogFiles_v2(vctx, &retrieve);
                
                if ( rv == SKLOG_FAILURE ) {
					ERROR("SKLOG_V_RetrieveLogFiles() failure");
					goto terminate;
				}
				
                print_result(vctx);
                
                break;
                
            case 'V':
            case 'v':

				line = readline("select logfile id: ");
				memcpy(cmd, line, strlen(line));
				free(line);
				
				if ( cmd[0] == 'x' || cmd[0] == 'X' )
					break;
					
				if ( cmd[0] == 'h' || cmd[0] == 'H') {
					help();
					break;
				}
				
                sscanf(cmd, "%d", &id);

                /*
                 * Verify
                 * 
                 */
                 
                rv = SKLOG_V_VerifyLogFile_v2(vctx,
					vctx->verifiable_logfiles[id], verify);

                if ( rv == SKLOG_FAILURE ) {
                    ERROR("SKLOG_V_VerifyLogFile() failure");
                    printf("verification result: LOGFILE VERIFICATION FAILS!\n");
                } else {
                    printf("verification result: LOGFILE VERIFICATION SUCCESS!\n");
                }
				
                break;
                
            case 'X':
            case 'x':
                fprintf(stdout,"  Bye...\n");
                goto terminate;
                
            default:
                fprintf(stdout,"\n\n  Unknown command\n\n");
                break;
        }
        
        
    }
    
terminate:
    SKLOG_V_FreeCtx(&vctx);
    return 0;
}


void prompt(char *cmd)
{
	char *buf = 0;
	buf = readline("verifier: ");
	
	if ( buf != NULL ) {
		memcpy(cmd, buf, strlen(buf));
		free(buf);
	}
}

void help(void)
{
	fprintf(stdout, "  H - show this help\n");
	fprintf(stdout, "  S - retrieve and show verifiable logfiles\n");
	fprintf(stdout, "  V - verify the selected logfile\n");
	fprintf(stdout, "  X - terminate this shell\n");
	
	return;
}

void print_result(SKLOG_V_Ctx *vctx)
{
	int i = 0;
	
	fprintf(stdout,"\n"
		"  Verifiable logfile at host %s\n"
		"  +------+--------------------------------------+\n"
		"  |   id | uuid                                 |\n"
		"  +------+--------------------------------------+\n",
		vctx->t_address);

		for ( i = 0 ; i < vctx->verifiable_logfiles_size ; i++ ) {
			if ( strlen(vctx->verifiable_logfiles[i]) > 0 ) 
				fprintf(stdout,"  | %4d | %s |\n", i,
					vctx->verifiable_logfiles[i]);
		}

		fprintf(stdout,
			"  +------+--------------------------------------+\n");
	
	return;
}
