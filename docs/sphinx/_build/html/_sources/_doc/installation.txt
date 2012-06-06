************
Installation
************

.. WARNING:: Since the library is in alpha release documentation 
	could not fit exactly the code

In this section is shown the procedure to install the library and to
configure the API environment.


Dependencies installation
=========================

Before proceeding with the installation, several dependencies need to 
be resolved::

    Libtool
    Autoconf
    OpenSSL >= 1.0.0
    SQLite 3.x
    libuuid
    libconfig
    libjansson >= 2.3.1
    libreadline

Here the command to run in Debian/Ubuntu systems::
    
    sudo aptitude install libtool autoconf libssl1.0.0 libssl-dev libsqlite3-0 libsqlite3-dev uuid-dev libconfig-dev libjansson-dev libreadline-dev
    
.. NOTE:: ``libjansson-dev`` (2.3.1) is **only available** for Wheezy (testing) and Sid (unstable) Debian releases. To install Libsklog on other systems you need to install it manually.
    
Get Libsklog sources
====================    

Get the sources from `Libsklog GitHub repository`_::

	cd $HOME
	mkdir temp
	cd temp
	git clone https://github.com/psmiraglia/Libsklog.git libsklog
	
Get Libumberlog_ sources ::

	cd $HOME/temp
	git clone https://github.com/algernon/libumberlog.git libumberlog
	
and install it 

	.. NOTE:: The usage of ``--prefix`` option is mandatory
	
::

	cd libumberlog
	./configure --prefix=$HOME/temp/libsklog/lib/libumbelog
	make
	make install

Installation
============
	
Generate ``./configure`` script (usually only the first time) using
:command:`autoreconf` ::

	cd $HOME/temp/libsklog
	git checkout --track origin/devel-rest
	autoreconf --install --force --verbose
	
Run ``./configure`` script using the options ``--enable-debug`` 
(strongly recommended) and ``--enable-encryption=no`` (to have human 
readable logs). Other options are available, to see them run::

	./configure --help
	
Build and install the library::

	./configure --enable-debug --enable-encryption=no
	make
	make install (as root)
	
If you are Debian addicted, you can use ``checkinstall`` instead
of ``make install``. In this way a .deb package will be created and
installed.::

	./configure --enable-debug --enable-encryption=no
	make
	checkinstall (as root)
	
.. _`Libsklog GitHub repository`: https://github.com/psmiraglia/Libsklog
.. _Libumberlog: https://github.com/algernon/libumberlog
