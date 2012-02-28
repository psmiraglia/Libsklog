install-data-local:
	if [ ! -d $(sysconfdir)/libsklog ]; then \
		mkdir -p $(sysconfdir)/libsklog ; \
	else \
		mkdir -p $(sysconfdir)/libsklog/python ; \
		sed "s|%%%LIBDIR%%%|$(libdir)|g" $(srcdir)/python/pysklog.py > $(sysconfdir)/libsklog/python/pysklog.py ; \
		cp $(srcdir)/python/unode.py $(sysconfdir)/libsklog/python/unode.py ;\
	fi
