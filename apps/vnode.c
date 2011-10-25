#include <sklog_v.h>

#define ADDRESS "127.0.0.1"
#define PORT 5555

int main (void) {

    SKLOG_V_Ctx *ctx = 0;

    ctx = SKLOG_V_NewCtx();

    SKLOG_V_InitCtx(ctx);

    //~ SKLOG_V_RetrieveLogFiles(ADDRESS,PORT);

    SKLOG_V_FreeCtx(&ctx);
        
    return 0;
}

