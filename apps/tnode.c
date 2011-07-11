#include <sklog_commons.h>
#include <sklog_t.h>

#include <sys/time.h>

int main ( void ) {

    SKLOG_T_Ctx t_ctx;


    
    if ( SKLOG_T_InitCtx(&t_ctx) == SKLOG_FAILURE ) {
        //~ error
        return 1;
    }

    SKLOG_T_Run(&t_ctx);

    return 0;
}
