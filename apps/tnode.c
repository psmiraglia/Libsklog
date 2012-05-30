#include <sklog_t.h>

int main ( void ) {

    SKLOG_T_Ctx *ctx = 0;
    
    /* create and initialize a new context*/

    ctx = SKLOG_T_NewCtx();

    if ( ctx == NULL ) {
        fprintf(stderr,"SKLOG_T_NewCtx() failure\n");
        return 1;
    } 

    if ( SKLOG_T_InitCtx(ctx) == SKLOG_FAILURE ) {
        fprintf(stderr,"SKLOG_T_InitCtx() failure\n");
        return 1;
    }
    
    /* run sample T server application */

    SKLOG_T_RunServer(ctx);
    
    /* free context */

    SKLOG_T_FreeCtx(&ctx);
    
    return 0;
}
