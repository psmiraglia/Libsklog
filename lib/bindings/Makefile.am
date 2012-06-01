install-data-local:
	mkdir -p $(sysconfdir)/libsklog/python ; \
	mkdir -p $(sysconfdir)/libsklog/python/apps ; \
	sed "s|%%%LIBDIR%%%|$(libdir)|g" $(srcdir)/python/pysklog.py > $(sysconfdir)/libsklog/python/pysklog.py ; \
	sed "s|%%%LIBDIR%%%|$(libdir)|g" $(srcdir)/python/apps/RESTserver.py > $(sysconfdir)/libsklog/python/apps/RESTserver.py ; \
	sed "s|%%%LIBDIR%%%|$(libdir)|g" $(srcdir)/python/apps/RESTclient.py > $(sysconfdir)/libsklog/python/apps/RESTclient.py ; \
	cp -vf $(srcdir)/python/apps/rawdata.dat $(sysconfdir)/libsklog/python/apps/ ; \
	ln -s $(sysconfdir)/libsklog/python/pysklog.py $(sysconfdir)/libsklog/python/apps/pysklog.py
