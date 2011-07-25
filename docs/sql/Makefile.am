install-data-local:
	if [ ! -d $(sysconfdir)/libsklog ]; then \
		mkdir -p $(sysconfdir)/libsklog/sql ; \
	else \
		mkdir $(sysconfdir)/libsklog/sql ; \
	fi && \
	cp $(srcdir)/*.sql $(sysconfdir)/libsklog/sql && \
	if [ ! -d $(localstatedir)/libsklog]; then \
		mkdir -p $(localstatedir)/libsklog ; \
	fi && \
	mkdir -p $(localstatedir)/libsklog/db && \
	sqlite3 $(localstatedir)/libsklog/db/t.db "" && \
	sqlite3 $(localstatedir)/libsklog/db/u.db ""
