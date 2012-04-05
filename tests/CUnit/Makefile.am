CUNITPATH = $(srcdir)/CUnit

noinst_PROGRAMS = sklog_tests

sklog_tests_SOURCES = \
	sklog_tests.c sklog_tests.h \
	u_tests.c t_tests.c v_tests.c
	
sklog_tests_CFLAGS = -Wall -Werror -g -O0 \
	-DVAR_PREFIX=\"@localstatedir@\" \
	-I$(srcdir)/../../include -I$(CUNITPATH)/lib/include
sklog_tests_LDFLAGS = -L$(CUNITPATH)/lib -lcunit
sklog_tests_LDADD = ../../lib/libsklog.la
