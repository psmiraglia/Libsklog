*************
Configuration
*************

In Schneier and Kelsey logging scheme, three entities are defined

* U is an **untrusted** entity which produces logentries

* T is a **trusted** entity which interacts with U and V

* V is an **external** entity who wants to access/verify the collected logentries

For each entity, Libsklog provides a set of APIs, each of which needs to
be configured. To perform the configuration users have to edit the
configuration files placed in ``$PREFIX/etc/libsklog``.


``libsklog-u.conf``
===================

+------------------+--------+---------------------------------------------------------------------+
| Parameter        | Type   | Description                                                         |
+==================+========+=====================================================================+
| ``ca_cert``      | String | Specifies the CA certificate file path                              |
+------------------+--------+---------------------------------------------------------------------+
| ``t_address``    | String | Specifies the address of T                                          |
+------------------+--------+---------------------------------------------------------------------+
| ``t_port``       | Int    | Specifies the port of T                                             |
+------------------+--------+---------------------------------------------------------------------+
| ``u_cert``       | String | Specifies the U certificate file path                               |
+------------------+--------+---------------------------------------------------------------------+
| ``u_privkey``    | String | Specifies the U private key file path                               |
+------------------+--------+---------------------------------------------------------------------+
| ``u_id``         | String | Specifies the identifier of U (common name in the certificate)      |
+------------------+--------+---------------------------------------------------------------------+
| ``u_timeout``    | Int    | Specifies the timeout for the logging session initialization        |
+------------------+--------+---------------------------------------------------------------------+
| ``logfile_size`` | Int    | Specifies the maximum number of logentries for each logging session |
+------------------+--------+---------------------------------------------------------------------+

Example::

	#--------------------------#
	# U API configuration file #
	#--------------------------#
	
	t_cert="ca_cert.pem"
	t_address = "127.0.0.1"
	t_port = 5555
	
	u_cert="u1_cert.pem"
	u_privkey="u1_key.pem"
	
	u_id="u1.example.com"
	
	u_timeout = 30 
	
	logfile_size = 7



``libsklog-t.conf``
===================

+------------------+--------+---------------------------------------------------------------------+
| Parameter        | Type   | Description                                                         |
+==================+========+=====================================================================+
| ``t_cert``       | String | Specifies the T certificate file path                               |
+------------------+--------+---------------------------------------------------------------------+
| ``t_privkey``    | String | Specifies the T private key file path                               |
+------------------+--------+---------------------------------------------------------------------+
| ``t_address``    | String | Specifies the T binding address                                     |
+------------------+--------+---------------------------------------------------------------------+
| ``t_port``       | Int    | Specifies the T binding port                                        |
+------------------+--------+---------------------------------------------------------------------+
| ``t_id``         | String | Specifies the identifier of T (common name in the certificate)      |
+------------------+--------+---------------------------------------------------------------------+

Example::

	#--------------------------#
	# T API configuration file #
	#--------------------------#
	
	t_cert="ca_cert.pem"
	t_privkey="t_key.pem"
	
	t_address = "127.0.0.1"
	t_port = 5555
	
	t_id="t.example.com"


``libsklog-v.conf``
===================

.. NOTE::
	Not yet implemented. The APIs use default values.



