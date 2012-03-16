CMOCKERYDIR=$(srcdir)/cmockery


noinst_PROGRAMS = sklog_tests

sklog_tests_SOURCES = \
	run_tests.c sklog_tests.h \
	u_tests.c t_tests.c v_tests.c
	
sklog_tests_CFLAGS = -Wall -Werror -I$(CMOCKERYDIR)/include -I$(srcdir)/../include
sklog_tests_LDLAGS = -lcmockery -lsklog
sklog_tests_LDADD = \
	$(CMOCKERYDIR)/lib/libcmockery.la \
	../lib/libsklog.la
