***************
Python Bindings
***************

.. WARNING:: Since the library is in alpha release documentation 
	could not fit exactly the code
	
:mod:`pysklog` --- Libsklog Python Bindings
===========================================

.. py:module:: pysklog
	:synopsis: Libsklog Python Bindings

To access the API users need to import the :mod:`pysklog` module ::

	import pysklog
	
	...

Module description
==================


.. py:class:: Sklog_U

	.. py:method:: open_logging_session()
	
	Initializes a new logging session.
	
	.. py:method:: log_event(event_type, event)
	
	Logs an ``event`` event of type ``event_type``.
	
	.. py:method:: close_logging_session()
	
	Closes an already opened logging session.

.. py:class:: Sklog_T

	.. py:method:: manage_loggins_session_init(m0_msg)
	
	Manages a logging session initialization request.
	
	.. py:method:: manage_logfile_retrieve()
	
	Manages a logfiles retrieve request.
	
	.. py:method:: manage_logfile_verify(logfile_id)
	
	Manages a logfile verify request.

.. py:class:: Sklog_V

	.. WARNING:: Not yet implemented




