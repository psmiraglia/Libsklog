#include <sklog_v.h>

#define RBUF_LEN 1024

void show_menu(void);

int main (int argc, char **argv) {

    SKLOG_V_Ctx *vctx = 0;
    SKLOG_CONNECTION *c = 0;

    char rbuf[RBUF_LEN] = { 0 };
    int index = 0;

    char inbuf[INBUF_LEN] = {0};

    int retval = 0;

    vctx = SKLOG_V_NewCtx();

    SKLOG_V_InitCtx(vctx);


    while ( 1 ) {

        show_menu();
        memset(inbuf,0,INBUF_LEN); gets(inbuf);
        
        switch ( inbuf[0] ) {
            case 'S':
            case 's':

                //~ open connection
                if ( ( c = new_connection()) == 0 ) {
                    ERROR("new_connection() failure");
                    goto terminate;
                }
            
                retval = setup_ssl_connection(c,vctx->t_address,vctx->t_port,
                                              vctx->v_cert,vctx->v_privkey,
                                              vctx->t_cert_file_path,DO_NOT_VERIFY);
            
                if ( retval == SKLOG_FAILURE ) {
                    ERROR("setup_ssl_connection() failure");
                    goto terminate;
                }

                //----------------------------------------------------//

                

                fprintf(stdout,"\nVerifiable logfile available at %s:%d\n---------------------------------------------------------------------\n",
                    vctx->t_address,vctx->t_port);
                    
                SKLOG_V_RetrieveLogFiles(vctx,c);

                fprintf(stdout,"    id | uuid\n  --------------------------------------------\n",
                    index,vctx->verifiable_logfiles[index]);

                for ( index = 0 ; index < 256 ; index++ ) {
                    if ( strlen(vctx->verifiable_logfiles[index]) > 0 ) 
                        fprintf(stdout,"   %3d | %s\n",index,vctx->verifiable_logfiles[index]);
                }

                //----------------------------------------------------//
                
                //~ close connection
                destroy_ssl_connection(c);
                free_conenction(c);

                break;
            case 'V':
            case 'v':

                fprintf(stdout,"\nSelect logfile id: ");
                memset(inbuf,0,INBUF_LEN); gets(inbuf);

                sscanf(inbuf,"%d",&index);

                //~ open connection
                if ( ( c = new_connection()) == 0 ) {
                    ERROR("new_connection() failure");
                    goto terminate;
                }
            
                retval = setup_ssl_connection(c,vctx->t_address,vctx->t_port,
                                              vctx->v_cert,vctx->v_privkey,
                                              vctx->t_cert_file_path,DO_NOT_VERIFY);
            
                if ( retval == SKLOG_FAILURE ) {
                    ERROR("setup_ssl_connection() failure");
                    goto terminate;
                }

                //----------------------------------------------------//

                if ( SKLOG_V_VerifyLogFile(vctx,c,index) == SKLOG_FAILURE ) {
                    ERROR("SKLOG_V_VerifyLogFile() failure");
                }

                //----------------------------------------------------//
                
                //~ close connection
                destroy_ssl_connection(c);
                free_conenction(c);
                
                break;
            case 'X':
            case 'x':
                fprintf(stdout,"Bye...\n");
                goto terminate;
            default:
                fprintf(stdout,"\n\nUnknown command\n\n");
                break;
        }
        
        
    }
    
terminate:

    SKLOG_V_FreeCtx(&vctx);
        
    return 0;
}


void show_menu(void)
{
    const char *menu = "\n\
Verifier Action Menu:\n\
---------------------------------------------------------------------\n\
  - show verifiable logfiles [s]\n\
  - verify logfile [v]\n\
  - exit [x]\n\
\n\
Select action: ";

    fprintf(stdout,"%s",menu);
}

