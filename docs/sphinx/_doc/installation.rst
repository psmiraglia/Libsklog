************
Installation
************

.. WARNING:: Since the library is in alpha release documentation 
	could not fit exactly the code

In this section is shown the procedure to install the library and to
configure the API environment. All steps are described assuming that the
library installation prefix is::

   /usr/local


Get Sources and Install Library
===============================

Before proceeding with the installation, several dependencies need to 
be resolved::

    Libtool
    Autoconf
    OpenSSL >= 1.0.0
    SQLite 3.x
    libuuid
    libconfig
    libjansson

Here the command to run in Debian/Ubuntu systems::
    
    sudo aptitude install libtool autoconf libssl1.0.0 libssl-dev libsqlite3-0 libsqlite3-dev uuid-dev libconfig-dev libjansson-dev

Get the sources from `Libsklog GitHub repository`_::

	mkdir ~/temp
	cd ~/temp
	git clone https://github.com/psmiraglia/Libsklog.git libsklog
	
Generate ``./configure`` script (usually only the first time)::

	cd libsklog
	git checkout --track origin/devel-rest
	autoreconf --install --force --verbose
	
Run ``./configure`` script using the option ``--enable-debug`` (strongly
recommended). Other options are available, to see them run::

	./configure --help
	
Build and install the library::

	./configure --enable-debug
	make
	make install (as root)
	
If you are Debian addicted, you can use ``checkinstall`` instead
of ``make install``. In this way a .deb package will be created and
installed.::

	./configure --enable-debug
	make
	checkinstall (as root)
	
.. _`Libsklog GitHub repository`: https://github.com/psmiraglia/Libsklog
