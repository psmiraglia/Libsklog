#include <unistd.h>

#include <sklog_commons.h>
#include <sklog_u.h>

int main (void) {

    SKLOG_RETURN retval = 0;

    SKLOG_U_Ctx *u_ctx = SKLOG_U_NewCtx();

    retval = SKLOG_U_CreateLogentry(u_ctx,NoType,"Until the philosophy\0",strlen("Until the philosophy\0"));

    if ( retval == SKLOG_FAILURE ) {
        ERROR("SKLOG_U_CreateLogentry() failure");
        return 1;
    }
    sleep(2);

    retval = SKLOG_U_CreateLogentry(u_ctx,NoType,"which hold one race superior\0",strlen("which hold one race superior\0"));
    if ( retval == SKLOG_FAILURE ) {
        ERROR("SKLOG_U_CreateLogentry() failure");
        return 1;
    }
    sleep(2);

    retval = SKLOG_U_CreateLogentry(u_ctx,NoType,"and another inferior\0",strlen("and another inferior\0"));
    if ( retval == SKLOG_FAILURE ) {
        ERROR("SKLOG_U_CreateLogentry() failure");
        return 1;
    }
    sleep(2);

    retval = SKLOG_U_CreateLogentry(u_ctx,NoType,"every where is war!\0",strlen("every where is war!\0"));
    if ( retval == SKLOG_FAILURE ) {
        ERROR("SKLOG_U_CreateLogentry() failure");
        return 1;
    }
    sleep(2);
        
    return 0;
}

