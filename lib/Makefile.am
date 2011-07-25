lib_LTLIBRARIES = libsklog.la

libsklog_la_SOURCES = \
	sklog_commons.h \
	sklog_err.c sklog_err.h \
	sklog_internal.c sklog_internal.h \
	sklog_t.c sklog_t.h \
	sklog_u.c sklog_u.h \
	sklog_v.c sklog_v.h \
	sklog_utils.c sklog_utils.h \
	storage/sklog_sqlite.c storage/sklog_sqlite.h \
	storage/sklog_file.c storage/sklog_file.h

libsklog_la_CFLAGS = -Wall -Werror \
	-DETC_PREFIX=\"@sysconfdir@\" \
	-DVAR_PREFIX=\"@localstatedir@\" \
	-DUSE_SQLITE

libsklog_la_LDFLAGS = \
	--version-info $(LIB_VERSION) \
	-lconfuse -lcrypto -lssl \
	-luuid -lsqlite3

