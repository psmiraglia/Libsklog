install-data-local:
	if [ ! -d $(sysconfdir)/libsklog ]; then \
		mkdir -p $(sysconfdir)/libsklog ; \
	fi ; \
	sed "s|%%%SYSCONFDIR%%%|$(sysconfdir)|g" \
		$(srcdir)/libsklog-u.conf.example > $(sysconfdir)/libsklog/libsklog-u.conf.example && \
	sed "s|%%%SYSCONFDIR%%%|$(sysconfdir)|g" \
		$(srcdir)/libsklog-t.conf.example >	$(sysconfdir)/libsklog/libsklog-t.conf.example
