install-data-local:
	if [ ! -d $(sysconfdir)/libsklog ]; then \
		mkdir -p $(sysconfdir)/libsklog ; \
	fi ; \
	mkdir -p $(sysconfdir)/libsklog/certs && \
	mkdir $(sysconfdir)/libsklog/certs/private && \
	mkdir $(sysconfdir)/libsklog/certs/ca && \
 	cp $(srcdir)/ca/ca_cert.pem $(sysconfdir)/libsklog/certs/ca && \
 	cp $(srcdir)/ca/ca_key.pem $(sysconfdir)/libsklog/certs/private && \
 	cp $(srcdir)/u1/u1_cert.pem $(sysconfdir)/libsklog/certs && \
 	cp $(srcdir)/u1/u1_key.pem $(sysconfdir)/libsklog/certs/private

