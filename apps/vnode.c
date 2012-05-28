#include <sklog_v.h>

#define RBUF_LEN 1024

void main_menu(void);

void show_menu(void);

int main (int argc, char **argv) {

    SKLOG_V_Ctx *vctx = 0;
    SKLOG_CONNECTION *c = 0;

    //~ char rbuf[RBUF_LEN] = { 0 };
    int index = 0;

    char inbuf[INBUF_LEN] = {0};

    int retval = 0;

    vctx = SKLOG_V_NewCtx();

    SKLOG_V_InitCtx(vctx);

    fprintf(stdout,"Welcome to Libsklog verifier shell!\nPress H to visualize the available commands or X to quit.\n");

    while ( 1 ) {

        main_menu();

        memset(inbuf,0,INBUF_LEN);
        gets(inbuf);
        
        switch ( inbuf[0] ) {
            case 'H':
            case 'h':
                fprintf(stdout,"  H - show this help\n");
                fprintf(stdout,"  S - retrieve and show verifiable logfiles\n");
                fprintf(stdout,"  V - verify the selected logfile\n");
                fprintf(stdout,"  X - terminate the shell\n");
                break;
            case 'S':
            case 's':

                //~ open connection
                if ( ( c = SKLOG_CONNECTION_New()) == 0 ) {
                    ERROR("SKLOG_CONNECTION_New() failure");
                    goto terminate;
                }
            
                //~ retval = setup_ssl_connection(c,vctx->t_address,vctx->t_port,
                                              //~ vctx->v_cert,vctx->v_privkey,
                                              //~ vctx->t_cert_file_path,DO_NOT_VERIFY);
                                              
				retval = SKLOG_CONNECTION_Init(c, vctx->t_address, vctx->t_port,
					vctx->v_cert, vctx->v_privkey,
					vctx->t_cert_file_path, DO_NOT_VERIFY);
				            
                if ( retval == SKLOG_FAILURE ) {
                    ERROR("SKLOG_CONNECTION_Init() failure");
                    goto terminate;
                }

                //----------------------------------------------------//
                //----------------------------------------------------//

                /*
                fprintf(stdout,
                    "\nVerifiable logfile available at %s:%d"\
                    "\n---------------------------------------------------------------------\n",
                    vctx->t_address,vctx->t_port);
                */
                    
                SKLOG_V_RetrieveLogFiles(vctx,c);
                
                NOTIFY("I'm here...");

                fprintf(stdout,"\n"\
                    "  Verifiable logfile at host %s\n"\
                    "  +------+--------------------------------------+\n"\
                    "  |   id | uuid                                 |\n"\
                    "  +------+--------------------------------------+\n",
                    vctx->t_address);

                for ( index = 0 ; index < vctx->verifiable_logfiles_size ; index++ ) {
                    if ( strlen(vctx->verifiable_logfiles[index]) > 0 ) 
                        fprintf(stdout,"  | %4d | %s |\n",index,vctx->verifiable_logfiles[index]);
                }

                fprintf(stdout,
                    "  +------+--------------------------------------+\n");

                //----------------------------------------------------//
                //----------------------------------------------------//
                
                //~ close connection
                //~ destroy_ssl_connection(c);
                //~ free_conenction(c);
                SKLOG_CONNECTION_Destroy(c);
                SKLOG_CONNECTION_Free(&c);

                break;
            case 'V':
            case 'v':

                fprintf(stdout,"\n  select logfile id: ");
                memset(inbuf,0,INBUF_LEN); gets(inbuf);

                sscanf(inbuf,"%d",&index);

                //~ open connection
                if ( ( c = SKLOG_CONNECTION_New()) == 0 ) {
                    ERROR("SKLOG_CONNECTION_New() failure");
                    goto terminate;
                }
            
                //~ retval = setup_ssl_connection(c,vctx->t_address,vctx->t_port,
                                              //~ vctx->v_cert,vctx->v_privkey,
                                              //~ vctx->t_cert_file_path,DO_NOT_VERIFY);
                                              
                retval = SKLOG_CONNECTION_Init(c, vctx->t_address, vctx->t_port,
					vctx->v_cert, vctx->v_privkey,
					vctx->t_cert_file_path, DO_NOT_VERIFY);
            
                if ( retval == SKLOG_FAILURE ) {
                    ERROR("SKLOG_CONNECTION_Init() failure");
                    goto terminate;
                }

                //----------------------------------------------------//

                if ( SKLOG_V_VerifyLogFile(vctx,c,index) == SKLOG_FAILURE ) {
                    ERROR("SKLOG_V_VerifyLogFile() failure");
                    fprintf(stdout,"  LOGFILE VERIFICATION FAILS!!!\n");
                } else {
                    fprintf(stdout,"  LOGFILE VERIFICATION SUCCESSFUL!!!\n");
                }

                //----------------------------------------------------//
                
                //~ close connection
                //~ destroy_ssl_connection(c);
                //~ free_conenction(c);
                SKLOG_CONNECTION_Destroy(c);
                SKLOG_CONNECTION_Free(&c);
                
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


void main_menu(void)
{
    fprintf(stdout,"\nverifier: ");
}

