:tocdepth: 2

********
Tutorial
********

.. WARNING:: Since the library is in alpha release documentation 
	could not fit exactly the code

.. highlight:: c

Preliminaries
=============

To build application that use Libsklog it's necessary to add 
``-I/urs/local/include`` to ``CFLAGS`` and ``-L/usr/local/lib 
-lsklog`` to ``LDFLAGS`` ::
	
	gcc -Wall -Werror -I/urs/local/include my_log_app.c -o my_log_app.bin -L/usr/local/lib -lsklog
	
Probably to run your application you will need to set ``LD_LIBRARY_PATH`` environment variable::

	LD_LIBRARY_PATH=/usr/local/lib ./my_log_app.bin
	
Sample C applications
=====================

Libsklog library is provided with three sample application: 
``unode``, ``tnode``, ``vnode``.

``tnode``
^^^^^^^^^

**Description**

	The application simulates a T service running on a server. Listening
	IP address and binding port may be defined in
	``$PREFIX/etc/libsklog/libsklog-t.conf`` file. Default values are
	``127.0.0.1`` and ``5000``. During the execution a certificate password
	is requested. Use ``123456`` password.

**Usage**
	:: 

	$> cd $PREFIX/bin
	$> ./tnode

**Source**

.. literalinclude:: ../../../apps/tnode.c
	:language: c
	:linenos:
	:tab-width: 4
		
``unode``
^^^^^^^^^

**Description**

	The application simulates a flood of event log generation. The event
	descriptions are read from file ``rawdata.dat`` which contains one
	event per line. The number of events in ``rawdata.dat`` file, forces
	the application to initialize three logging session.

**Usage**

	.. NOTE:: An already running ``tnode`` is required
	
	::
		
		$> cd $PREFIX/bin
		$> ./unode
	
**Source**

.. literalinclude:: ../../../apps/unode.c
	:language: c
	:linenos:
	:tab-width: 4
		
``vnode``
^^^^^^^^^

**Description**

	The application simulates an external viewer V who wants to retrieve
	and verify the logs. Such as application provides an interactive
	shell.
	
		 

**Usage**
 	
	::

		$> cd $PREFIX/bin
		$> ./vnode
		Welcome to Libsklog verifier shell
		Press H to visualize the available commands or X to quit.
		verifier:
	
**Source**

.. literalinclude:: ../../../apps/vnode.c
	:language: c
	:linenos:
	:tab-width: 4
		
Sample Python applications
==========================

Preliminaries
^^^^^^^^^^^^^

	TODO

RESTserver.py
^^^^^^^^^^^^^

**Description**

**Usage**

	::
	
		$> cd $PREFIX/etc/libsklog/python/apps
		$> python RESTserver.py
		
		Bottle server starting up (using WSGIRefServer())...
		Listening on http://127.0.0.1:9000/
		Hit Ctrl-C to quit.

**Source**

.. literalinclude:: ../../../lib/bindings/python/apps/RESTserver.py
	:language: py
	:linenos:
	:tab-width: 4

RESTclient.py
^^^^^^^^^^^^^

**Description**

**Usage**

	::
	
		$> cd $PREFIX/etc/libsklog/python/apps
		$> python RESTclient.py
		
**Note**

	This application simulates a process that logs dummy events. To
	retrieve log files and/or verify a logfile use ``curl`` as follow.
	
	Retrieve ::
	
		$> curl -d'{"operation":"retrieveLogfiles"}' -H'Content-type: application/json'  http://localhost:9000/logservice
		
	Verify ::
		
		$> curl -d'{"operation":"verifyLogfile","data":{"logfile_id":"ad96e592-abeb-11e1-a0b0-0025b345ca14"}}' -H'Content-type: application/json'  http://localhost:9000/logservice

**Source**

.. literalinclude:: ../../../lib/bindings/python/apps/RESTclient.py
		:language: py
		:linenos:
		:tab-width: 4
