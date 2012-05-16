SUBDIRS = bindings

lib_LTLIBRARIES = libsklog.la

libsklog_la_SOURCES = \
		sklog_commons.h sklog_commons.c \
		sklog_err.c sklog_err.h \
		sklog_internal.c sklog_internal.h \
		sklog_t.c sklog_t.h \
		sklog_t_internal.c sklog_t_internal.h \
		sklog_u.c sklog_u.h \
		sklog_u_internal.c sklog_u_internal.h \
		sklog_v.c sklog_v.h \
		sklog_utils.c sklog_utils.h
		
if HAVE_STORAGE_SQLITE
libsklog_la_SOURCES += storage/sklog_sqlite.c storage/sklog_sqlite.h
endif

if HAVE_STORAGE_FILE
libsklog_la_SOURCES += storage/sklog_file.c storage/sklog_file.h
endif

if HAVE_STORAGE_SYSLOG
libsklog_la_SOURCES += storage/sklog_syslog.c storage/sklog_syslog.h
endif

if HAVE_STORAGE_NONE
libsklog_la_SOURCES += \
	storage/sklog_dummy.c storage/sklog_dummy.h \
	storage/sklog_sqlite.c storage/sklog_sqlite.h
endif

if HAVE_PYTHON
libsklog_la_SOURCES += bindings/python/pylibsklog.c
endif

libsklog_la_CFLAGS = \
	@DBGFLAGS@ \
	-Wall -Werror \
	-DETC_PREFIX=\"@sysconfdir@\" \
	-DVAR_PREFIX=\"@localstatedir@\" \
	-I@SSLDIR@/include
	
if HAVE_PYTHON
libsklog_la_CFLAGS += @PY_CFLAGS@
endif

libsklog_la_LDFLAGS = \
	--version-info $(LIB_VERSION) \
	-luuid -lconfig \
	-L@SSLDIR@/lib -lcrypto -lssl

if HAVE_STORAGE_SQLITE
libsklog_la_LDFLAGS += -lsqlite3
endif

if HAVE_STORAGE_NONE
libsklog_la_LDFLAGS += -lsqlite3
endif
	
if HAVE_PYTHON
libsklog_la_LDFLAGS += @PY_LDFLAGS@
endif
