#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <google/cmockery.h>
#include <stdio.h>
#include <dirent.h>


/* U tests constructor */

void u_test_context_init(void **state);
void u_test_context_free(void **state);
void u_test_context_mgmt(void **state);

void u_test_open_params(void **state);

/* T tests constructor */

void t_test_context_init(void **state);
void t_test_context_free(void **state);
void t_test_context_mgmt(void **state);

/* V tests constructor */

void v_test_context_init(void **state);
void v_test_context_free(void **state);
void v_test_context_mgmt(void **state);
