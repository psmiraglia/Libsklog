install-local-data:
	if [ ! -d $(sysconfdir)/libsklog ]; then \
		mkdir -p $(sysconfdir)/libsklog ; \
	fi; \
	sed "s|%%%SYSCONFDIR%%%|$(sysconfdir)|g" \
		$(srcdir)/libsklog-u.conf.examle > \
			$(sysconfdir)/libsklog/libsklog-u.conf.example && \
	sed "s|%%%SYSCONFDIR%%%|$(sysconfdir)|g" \
		$(srcdir)/libsklog-t.conf.example > \
			$(sysconfdir)/libsklog/libsklog-t.conf.example
