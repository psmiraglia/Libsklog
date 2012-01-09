install-data-local:
	if [ ! -d $(sysconfdir)/libsklog ]; then \
		mkdir -p $(sysconfdir)/libsklog ; \
	fi ; \
	if [ ! -d $(sysconfdir)/libsklog/certs ]; then \
		mkdir -p $(sysconfdir)/libsklog/certs ; \
		cp $(srcdir)/u1/u1_cert.pem $(sysconfdir)/libsklog/certs ; \
		cp $(srcdir)/v/v_cert.pem $(sysconfdir)/libsklog/certs ; \
	fi ; \
	if [ ! -d $(sysconfdir)/libsklog/certs/private ]; then \
		mkdir $(sysconfdir)/libsklog/certs/private ; \
		cp $(srcdir)/ca/ca_key.pem $(sysconfdir)/libsklog/certs/private ; \
		cp $(srcdir)/u1/u1_key.pem $(sysconfdir)/libsklog/certs/private ; \
		cp $(srcdir)/v/v_key.pem $(sysconfdir)/libsklog/certs/private ; \
	fi ; \
	if [ ! -d $(sysconfdir)/libsklog/certs/ca ]; then \
		mkdir $(sysconfdir)/libsklog/certs/ca ; \
		cp $(srcdir)/ca/ca_cert.pem $(sysconfdir)/libsklog/certs/ca ; \
	fi
