lib_LTLIBRARIES = libsklog.la

libsklog_la_SOURCES = \
	sklog_commons.h \
	sklog_err.c sklog_err.h \
	sklog_internal.c sklog_internal.h \
	sklog_t.c sklog_t.h \
	sklog_u.c sklog_u.h \
	sklog_v.c sklog_v.h \
	sklog_utils.c sklog_utils.h

libsklog_la_CFLAGS = -Wall -Werror \
	-DETC_PREFIX=\"@sysconfdir@\" \
	-DVAR_PREFIX=\"@localstatedir@\"

libsklog_la_LDFLAGS = --version-info $(LIB_VERSION) -lconfuse -lcrypto -lssl -luuid -lsqlite3

install-data-local:
	mkdir -p $(sysconfdir)/libsklog/certs && \
	mkdir $(sysconfdir)/libsklog/certs/private && \
	mkdir $(sysconfdir)/libsklog/certs/ca && \
	cp $(srcdir)/conf/libsklog-u.conf.example $(sysconfdir)/libsklog && \
	cp $(srcdir)/conf/libsklog-t.conf.example $(sysconfdir)/libsklog && \
	cp $(srcdir)/certs/ca/ca_cert.pem $(sysconfdir)/libsklog/certs/ca && \
	cp $(srcdir)/certs/ca/ca_key.pem $(sysconfdir)/libsklog/certs/private && \
	cp $(srcdir)/certs/u1/u1_cert.pem $(sysconfdir)/libsklog/certs && \
	cp $(srcdir)/certs/u1/u1_key.pem $(sysconfdir)/libsklog/certs/private && \
	sed "s|%%%SYSCONFDIR%%%|$(sysconfdir)|g" $(sysconfdir)/libsklog/libsklog-u.conf.example > $(sysconfdir)/libsklog/libsklog-u.conf && \
	sed "s|%%%SYSCONFDIR%%%|$(sysconfdir)|g" $(sysconfdir)/libsklog/libsklog-t.conf.example > $(sysconfdir)/libsklog/libsklog-t.conf && \
	mkdir -p $(localstatedir)/libsklog/db && \
	sqlite3 $(localstatedir)/libsklog/db/t.db "create table AUTH_KEYS(u_id varchar(64), auth_key varchar(32));" && \
	sqlite3 $(localstatedir)/libsklog/db/u.db "create table LOG_ENTRY(type varchar(8),data varchar(4096),hash varchar(64),hmac varchar(64));"


	



#if test ! -e $(sysconfdir)/libsklog/libsklog-u.conf.example; then mkdir -p $(sysconfdir)/libsklog && cp $(srcdir)/libsklog-u.conf.example $(sysconfdir)/libsklog/ && cp $(srcdir)/libsklog-t.conf.example $(sysconfdir)/libsklog/ ; fi
