install-data-local:
	if [ ! -d $(sysconfdir)/libsklog ]; then \
		mkdir -p $(sysconfdir)/libsklog/sql ; \
	else \
		mkdir $(sysconfdir)/libsklog/sql ; \
	fi ; \
	cp $(srcdir)/*.sql $(sysconfdir)/libsklog/sql ; \
	if [ ! -d $(localstatedir)/libsklog ]; then \
		mkdir -p $(localstatedir)/libsklog ; \
	fi ; \
	if [ ! -d $(localstatedir)/libsklog/db ]; then \
		mkdir -p $(localstatedir)/libsklog/db ; \
		/usr/bin/sqlite3 $(localstatedir)/libsklog/db/t.db < \
			$(sysconfdir)/libsklog/sql/t_database.sql ; \
		/usr/bin/sqlite3 $(localstatedir)/libsklog/db/u.db < \
			$(sysconfdir)/libsklog/sql/u_database.sql ; \
	fi
