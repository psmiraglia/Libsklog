#include "sklog_tests.h"

#include <sklog_u.h>

//~ void u_test_success(void **state) {
	//~ int test_finished = 1;
	//~ assert_true (test_finished);	
//~ }
//~ 
//~ void u_ctx_init(void **state) {
	//~ 
	//~ int test_finished = 0;
	//~ 
	//~ SKLOG_U_Ctx *ctx = 0;
	//~ long int ctx_ptr = 0;
	//~ 
	//~ ctx = SKLOG_U_NewCtx();
	//~ ctx_ptr = (long int) ctx;
	//~ 
	//~ assert_int_not_equal(0,ctx_ptr);
	//~ 
	//~ SKLOG_U_FreeCtx(&ctx);
	//~ ctx_ptr = (long int) ctx;
	//~ 
	//~ assert_int_equal(0,ctx_ptr);
	//~ 
	//~ test_finished = 1;
	//~ assert_true (test_finished);
//~ }


SKLOG_U_Ctx *gctx = 0;

void u_test_context_init(void **state) {
	gctx = SKLOG_U_NewCtx();
	assert_int_not_equal(0,(long int)gctx);
}

void u_test_context_free(void **state) {
	SKLOG_U_FreeCtx(&gctx);
	assert_int_equal(0,(long int)gctx);
}

void u_test_context_mgmt(void **state) {
	SKLOG_U_Ctx *ctx = 0;
	ctx = SKLOG_U_NewCtx();
	SKLOG_U_FreeCtx(&ctx);
	assert_true(1);
}

void u_test_open_params(void **state) {

	SKLOG_U_Ctx *ctx = 0;
	char *s1 = 0;
	char *s2 = 0;
	unsigned int s1l = 0;
	unsigned int s2l = 0;
	
	int rv = SKLOG_FAILURE;
	
	ctx = SKLOG_U_NewCtx();
	
	rv = SKLOG_U_Open(NULL,NULL,NULL,NULL,NULL);
	assert_int_equal(SKLOG_FAILURE,rv);
	
	rv = SKLOG_U_Open(NULL,&s1,&s1l,NULL,NULL);
	assert_int_equal(SKLOG_FAILURE,rv);
	
	rv = SKLOG_U_Open(NULL,&s1,&s1l,&s2,&s2l);
	assert_int_equal(SKLOG_FAILURE,rv);
	
	rv = SKLOG_U_Open(ctx,&s1,&s1l,&s2,&s2l);
	assert_int_equal(SKLOG_SUCCESS,rv);
	
	SKLOG_U_FreeCtx(&ctx);
}
