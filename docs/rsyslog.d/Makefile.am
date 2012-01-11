install-data-local:
	if [ ! -f $(sysconfdir)/rsyslog.d ]; then \
		mkdir -p $(sysconfdir)/rsyslog.d ; \
	fi ; \
	cp $(srcdir)/libsklog.conf $(sysconfdir)/rsyslog.d
