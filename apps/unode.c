#include <time.h>
#include <unistd.h>

#include <sklog_u.h>

#define MAX 10

int main (void) {

    SKLOG_RETURN retval = 0;

    SKLOG_U_Ctx *u_ctx = SKLOG_U_NewCtx();

    srand((unsigned)time(NULL));

    retval = SKLOG_U_LogEvent(u_ctx,NoType,"Until the philosophy\0",strlen("Until the philosophy\0"));

    if ( retval == SKLOG_FAILURE ) {
        ERROR("SKLOG_U_LogEvent() failure");
        return 1;
    }
    sleep(1 + rand() % MAX);

    retval = SKLOG_U_LogEvent(u_ctx,NoType,"which hold one race superior\0",strlen("which hold one race superior\0"));
    if ( retval == SKLOG_FAILURE ) {
        ERROR("SKLOG_U_LogEvent() failure");
        return 1;
    }
    sleep(1 + rand() % MAX);

    retval = SKLOG_U_LogEvent(u_ctx,NoType,"and another inferior\0",strlen("and another inferior\0"));
    if ( retval == SKLOG_FAILURE ) {
        ERROR("SKLOG_U_LogEvent() failure");
        return 1;
    }
    sleep(1 + rand() % MAX);

    retval = SKLOG_U_LogEvent(u_ctx,NoType,"every where is war!\0",strlen("every where is war!\0"));
    if ( retval == SKLOG_FAILURE ) {
        ERROR("SKLOG_U_LogEvent() failure");
        return 1;
    }

    SKLOG_U_FreeCtx(&u_ctx);
        
    return 0;
}

