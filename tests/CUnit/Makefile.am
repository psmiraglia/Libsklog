noinst_PROGRAMS = sklog_tests

sklog_tests_SOURCES = \
	sklog_tests.c sklog_tests.h \
	u_tests.c t_tests.c v_tests.c
	
sklog_tests_CFLAGS = -Wall -Werror -I$(srcdir)/../../include
sklog_tests_LDFLAGS = -lcunit
sklog_tests_LDADD = ../../lib/libsklog.la
