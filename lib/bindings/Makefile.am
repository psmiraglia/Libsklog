install-data-local:
	if [ ! -d $(sysconfdir)/libsklog/python ]; then \
		mkdir -p $(sysconfdir)/libsklog/python ; \
		sed "s|%%%LIBDIR%%%|$(libdir)|g" $(srcdir)/python/pysklog.py > $(sysconfdir)/libsklog/python/pysklog.py ; \
		sed "s|%%%LIBDIR%%%|$(libdir)|g" $(srcdir)/python/RESTserver.py > $(sysconfdir)/libsklog/python/RESTserver.py ; \
		cp $(srcdir)/python/unode.py $(sysconfdir)/libsklog/python/unode.py ;\
	fi
