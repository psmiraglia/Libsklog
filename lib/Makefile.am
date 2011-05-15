lib_LTLIBRARIES = libsklog.la

libsklog_la_SOURCES = \
	sklog.c sklog.h \
	sklog_internal.c sklog_internal.h \
	sklog_define.h

libsklog_la_CFLAGS = -Wall -Werror -DETC_PREFIX=\"@sysconfdir@\"

libsklog_la_LDFLAGS = --version-info $(LIB_VERSION) -lconfuse

install-data-local:
	if test ! -e $(sysconfdir)/libsklog/tpm.conf; then mkdir -p $(sysconfdir)/libsklog && cp $(srcdir)/tpm.conf $(sysconfdir)/libsklog/; fi


