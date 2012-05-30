:tocdepth: 3

**************
API References
**************

.. WARNING:: Since the library is in alpha release documentation 
	could not fit exactly the code

.. highlight:: c

Preliminaries
=============

To access the API users have to include one or more of these files::

   #include <sklog_u.h> // to access U API
   #include <sklog_t.h> // to access T API
   #include <sklog_v.h> // to access V API

Global types
============

.. c:type:: SKLOG_RETURN

	TODO

.. c:type:: SKLOG_DATA_TYPE

	TODO
	
.. c:type:: SKLOG_DUMP_MODE

	TOTO
	
.. c:type:: SKLOG_CONNECTION

	TODO
	
SKLOG_U APIs
============

Types
-----

.. c:type:: SKLOG_U_Ctx

	TODO

.. c:type:: SKLOG_U_STORAGE_DRIVER

	TODO

Functions
---------

SKLOG_U_NewCtx()
^^^^^^^^^^^^^^^^

**Synopsis**

	.. c:function:: SKLOG_U_Ctx *SKLOG_U_NewCtx(void)

**Description**
	
	Allocate a new ``SKLOG_U_Ctx`` structure.
	
**Return values**
	
	The function returns a valid pointer to a ``SKLOG_U_Ctx`` 
	structure in case of success, ``NULL`` in case of error.
	
SKLOG_U_InitCtx()
^^^^^^^^^^^^^^^^^

**Synopsis**

	.. c:function:: SKLOG_RETURN *SKLOG_U_InitCtx(SKLOG_U_Ctx *ctx)

**Description**
	
	Initialize the U API context ``ctx`` by reading the configuration
	file ``libsklog-u.conf``.
	
**Return values**
	
	The function returns ``SKLOG_SUCCES`` in case of success, 
	``SKLOG_FAILURE`` in case of failure.
	
SKLOG_U_Open_M0()
^^^^^^^^^^^^^^^^^

**Synopsis**

	.. c:function:: SKLOG_RETURN SKLOG_U_Open_M0(SKLOG_U_Ctx *ctx, \
		unsigned char **m0, unsigned int *m0_len, char **logentry, \
		unsigned int *logentry_len)

**Description**
	
	Executes the first step of the logging session initialization 
	phase. ``m0`` buffer, which is ``m0_len`` bytes length, will 
	contains the request message M0 as **binary blob**. The 
	``logentry`` buffer will contains the first logentry (that will 
	be ``logentry_len`` bytes long) of a new log file.
	
	
**Return values**
	
	The function returns ``SKLOG_SUCCES`` in case of success, 
	``SKLOG_FAILURE`` in case of failure.

SKLOG_U_Open_M1()
^^^^^^^^^^^^^^^^^

**Synopsis**

	.. c:function:: SKLOG_RETURN SKLOG_U_Open_M1(SKLOG_U_Ctx *ctx, \
		unsigned char *m1, unsigned int m1_len, char **logentry, \
		unsigned int *logentry_len)

**Description**
	
	Executes the second step of the logging session initialization 
	phase. The ``m1`` buffer, that is ``m1_len`` bytes long, will 
	contains the response message M1 as **binary blob**. The 
	``logentry`` buffer will contains the second logentry of a new 
	log file and will be ``logentry_len`` bytes long.
	
**Return values**
	
	The function returns ``SKLOG_SUCCES`` in case of success, 
	``SKLOG_FAILURE`` in case of failure.

SKLOG_U_LogEvent()
^^^^^^^^^^^^^^^^^^

**Synopsis**

	.. c:function:: SKLOG_RETURN SKLOG_U_LogEvent(SKLOG_U_Ctx *u_ctx, \
		SKLOG_DATA_TYPE type, char *event, unsigned int event_len, \
		char **logentry, unsigned int *logentry_len)
	
**Description**
	
	Log an event of type ``type`` described in the buffer ``event`` of 
	``event_len`` bytes and put the generated logenrty in the ``logentry`` 
	buffer that will be ``logentry_len`` bytes long.
	
**Notes**
	
	The generated logentry will be a JSON structure structured as follow::
	
		{
			"sk_session":"d8240caa-2d8f-4f72-9bce-7ba0972c9093",
			"sk_type":4,
			"sk_data":{
				"msg":"In mollis molestie imperdiet.",
				"pid":"0",
				"facility":"kern",
				"priority":"notice",
				"program":"(null)",
				"uid":"0",
				"gid":"0",
				"host":"",
				"timestamp":"2012-05-29T11:27:42.903558075+0200"
			},
			"sk_hash":"xBbvObUXnyTk+SGf+4yFMNvdKnutoj6l9SE5/nNBKGU=",
			"sk_hmac":"uAwkPwqvecbk7Zfw3Xhf0U1EJLL2HKMBuHvX1TrYYPk="
		}
	
	The ``sk_data`` object is a JSON structure generated using the 
	function ``ul_format()`` provided by the library ``libubmerlog``.
	For more details, see `Lumberjack Project`_ and Libumberlog_ web pages.
	
.. _`Lumberjack Project`: https://fedorahosted.org/lumberjack/
.. _Libumberlog: https://github.com/algernon/libumberlog

**Return values**
	
	The function returns ``SKLOG_SUCCES`` in case of success, 
	``SKLOG_FAILURE`` in case of failure.

SKLOG_U_FlushLogfile()
^^^^^^^^^^^^^^^^^^^^^^

.. WARNING:: Probably will be removed in next releases

**Synopsis**

	.. c:function:: SKLOG_RETURN SKLOG_U_FlushLogfile(SKLOG_U_Ctx *ctx, \
		char *logs[], unsigned int *logs_size)
	
**Description**

	Flush the current logging session. The function reads current
	logfile and put its content in ``logs`` which will contains 
	``logs_size`` elements.

**Return values**

	The function returns ``SKLOG_SUCCES`` in case of success, 
	``SKLOG_FAILURE`` in case of failure.
	
SKLOG_U_DumpLogfile()
^^^^^^^^^^^^^^^^^^^^^^^

**Synopsis**
	.. c:function:: SKLOG_RETURN SKLOG_U_DumpLogfile(SKLOG_U_Ctx *ctx, \
		const char *filename, SKLOG_DUMP_MODE dump_mode)
	
**Description**

	Generate a logentry dump for the current logging session. The dump
	will be	written in ``filename`` file. The flag ``dump_mode``
	specifies the dump format. Supported mode: ``DUMP_MODE_JSON``.
	
**Notes**
	
	Below is depicted the JSON dump structure. Each ``logentry`` 
	JSON array element is structured as previously described::
		
		{
			"session":"d8240caa-2d8f-4f72-9bce-7ba0972c9093",
			"logs":[
				{logentry},
				{logentry},
				{logentry},
				...
			]
		}
	
**Return values**

	The function returns ``SKLOG_SUCCES`` in case of success, 
	``SKLOG_FAILURE`` in case of failure.

SKLOG_U_Close()
^^^^^^^^^^^^^^^

**Synopsis**

	.. c:function:: SKLOG_RETURN SKLOG_U_Close(SKLOG_U_Ctx *u_ctx, \
		char **logentry, unsigned int *logentry_len)

**Description**
	
	Terminate an already opened logging session. This phase 
	generates the last logentry of the session. Such as logentry will
	be contained in ``logentry`` buffer that will be ``logentry_len``
	bytes long.
	
**Return values**
	
	The function returns ``SKLOG_SUCCES`` in case of success, 
	``SKLOG_FAILURE`` in case of failure.
	
SKLOG_U_FreeCtx()
^^^^^^^^^^^^^^^^^

**Synopsis**

	.. c:function:: SKLOG_RETURN SKLOG_U_FreeCtx(SKLOG_U_Ctx **ctx)

**Description**
	
	Free the memory allocated for ``ctx`` data structure.

**Return values**
	
	The function returns ``SKLOG_SUCCES`` in case of success, 
	``SKLOG_FAILURE`` in case of failure.

SKLOG_T APIs
============

Types
-----

.. c:type:: SKLOG_T_Ctx

	TODO
	
.. c:type:: SKLOG_T_STORAGE_DRIVER

	TODO

Functions
---------

SKLOG_T_NewCtx()
^^^^^^^^^^^^^^^^

**Synopsis**

	.. c:function:: SKLOG_T_Ctx* SKLOG_T_NewCtx(void)

**Description**

	Allocates a new ``SKLOG_T_Ctx`` empty structure.
	
**Return values**
	
	The function returns a valid pointer to a ``SKLOG_T_Ctx`` 
	structure in case of success, ``NULL`` in case of error.

SKLOG_T_InitCtx()
^^^^^^^^^^^^^^^^^

**Synopsis**

	.. c:function:: SKLOG_RETURN SKLOG_T_InitCtx(SKLOG_T_Ctx *ctx)

**Description**

	Initialize the T API context ``ctx`` by reading the configuration
	file ``libsklog-t.conf``.
	
**Return values**
	
	The function returns ``SKLOG_SUCCES`` in case of success, 
	``SKLOG_FAILURE`` in case of failure.
	
SKLOG_T_ManageLoggingSessionInit()
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Synopsis**

	.. c:function:: SKLOG_RETURN SKLOG_T_ManageLoggingSessionInit(SKLOG_T_Ctx *ctx, \
		unsigned char *m0, unsigned int m0_len, char *u_address, \
		unsigned char **m1, unsigned int *m1_len)
	
**Description**
	
	Manage the logging session initialization requests coming from a 
	client who has ``u_address`` IP address. The buffer ``m0``, that 
	is ``m0_len`` bytes long, contains the request data and the 
	buffer ``m1`` that will be ``m1_len`` bytes long, will contains 
	the response. Both the ``m0`` and ``m1`` buffers contain a 
	**binary blob**.
	
**Return values**	
	
	The function returns ``SKLOG_SUCCES`` in case of success, 
	``SKLOG_FAILURE`` in case of failure.

SKLOG_T_ManageLogfileUpload()
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. WARNING:: Probably will be removed in next release

**Synopsis**
	
	.. c:function:: SKLOG_RETURN SKLOG_T_ManageLogfileUpload(SKLOG_T_Ctx ctx, \
		SKLOG_CONNECTION *c)
	
**Description**
	
	TODO
	
**Return values**
	
	The function returns ``SKLOG_SUCCES`` in case of success, 
	``SKLOG_FAILURE`` in case of failure.
	
SKLOG_T_ManageLogfileRetrieve()
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Synopsis**

	.. c:function:: SKLOG_RETURN \
		SKLOG_T_ManageLogfileRetrieve(SKLOG_T_Ctx *ctx, \
		char *logfile_list[], unsigned int *logfile_list_len)

**Description**
	
	Manages the logfile retrieve requests. The array ``logfile_list``,
	that will be composed by ``logfile_list_len`` elements, 
	will contains a list of logging session id.
	
**Return values**
	
	The function returns ``SKLOG_SUCCES`` in case of success, 
	``SKLOG_FAILURE`` in case of failure.
	
SKLOG_T_ManageLogfileVerify()
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Synopsis**

	.. c:function:: SKLOG_RETURN \
		SKLOG_T_ManageLogfileVerify(SKLOG_T_Ctx *ctx, \
		char *logfile_id)
	
**Description**

	Manages the logfile verification requests. ``logfile_id`` specifies
	what is logfile that will be verified.
	
**Return values**
	
	The function returns ``SKLOG_SUCCES`` in case of verificatio success, 
	``SKLOG_VERIFICATION_FAILURE`` in case of verification failure and
	``SKLOG_FAILURE`` in case of error.

SKLOG_T_FreeCtx()
^^^^^^^^^^^^^^^^^

**Synopsis**

	.. c:function:: SKLOG_RETURN SKLOG_T_FreeCtx(SKLOG_T_Ctx **ctx)

**Description**

	Free the memory allocated for ``ctx`` structure.
	
**Return values**
	
	The function returns ``SKLOG_SUCCES`` in case of success, 
	``SKLOG_FAILURE`` in case of failure.

SKLOG_T_RunServer()
^^^^^^^^^^^^^^^^^^^

**Synopsis**

	.. c:function:: SKLOG_RETURN SKLOG_T_RunServer(SKLOG_T_Ctx *ctx)

**Description**
	
	Implements a simple T application. ``ctx`` is an already initialized
	context.
	
**Return values**
	
	The function returns ``SKLOG_SUCCES`` in case of success, 
	``SKLOG_FAILURE`` in case of failure.

SKLOG_V APIs
============

Types
-----

.. c:type:: SKLOG_V_Ctx

	TODO
	
.. c:type:: SKLOG_V_DATA_TRANSFER_CB

	TODO

Functions
---------

SKLOG_V_NewCtx()
^^^^^^^^^^^^^^^^

**Synopsis**
	
	.. c:function:: SKLOG_V_Ctx* SKLOG_V_NewCtx(void)

**Description**
	
	Allcoates a new  ``SKLOG_V_Ctx`` structure.
	
**Return values**
	
	The function returns a valid pointer to a ``SKLOG_V_Ctx`` 
	structure in case of success, ``NULL`` in case of error.

SKLOG_V_InitCtx()
^^^^^^^^^^^^^^^^^

**Synopsis**

	.. c:function:: SKLOG_RETURN SKLOG_V_InitCtx(SKLOG_V_Ctx *ctx)

**Description**
	
	Initialize the V API context ``ctx`` using default values.
	Configuration file parsing is **not yet implemented**.
	
**Return values**
	
	The function returns ``SKLOG_SUCCES`` in case of success, 
	``SKLOG_FAILURE`` in case of failure.

SKLOG_V_FreeCtx()
^^^^^^^^^^^^^^^^^

**Synopsis**
	
	.. c:function:: SKLOG_RETURN SKLOG_V_FreeCtx(SKLOG_V_Ctx **ctx)

**Description**
	
	Free the memory allocated for ``ctx`` structure.
	
**Return values**
	
	The function returns ``SKLOG_SUCCES`` in case of success, 
	``SKLOG_FAILURE`` in case of failure.

SKLOG_V_RetrieveLogFiles()
^^^^^^^^^^^^^^^^^^^^^^^^^^

.. WARNING:: Deprecated

**Synopsis**
	
	.. c:function:: SKLOG_RETURN \
		SKLOG_V_RetrieveLogFiles(SKLOG_V_Ctx *v_ctx, \
		SKLOG_CONNECTION *c)

**Description**

**Return values**
	
	The function returns ``SKLOG_SUCCES`` in case of success, 
	``SKLOG_FAILURE`` in case of failure.
	
SKLOG_V_RetrieveLogFiles_v2()
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Synopsis**
	
	.. c:function:: SKLOG_RETURN \
		SKLOG_V_RetrieveLogFiles_v2(SKLOG_V_Ctx *ctx, \
		SKLOG_V_DATA_TRANSFER_CB data_transfer_cb)
		
**Description**
	
	Sends logfile retrieve requests to T. The request result is 
	stored in ``ctx->verifiable_logfiles[]`` array that will contain 
	``ctx->verifiable_logfiles_size`` elements.
	
	For data transfering, users have to define a 
	``SKLOG_V_DATA_TRANSFER_CB`` callback (**EXPERIMENTAL**).
	
**Return values**
	
	The function returns ``SKLOG_SUCCES`` in case of success, 
	``SKLOG_FAILURE`` in case of failure.

SKLOG_V_VerifyLogFile()
^^^^^^^^^^^^^^^^^^^^^^^

.. WARNING:: Deprecated

**Synopsis**
	
	.. c:function:: SKLOG_RETURN SKLOG_V_VerifyLogFile(SKLOG_V_Ctx *v_ctx, SKLOG_CONNECTION *c, unsigned int logfile_id)

**Description**
	
**Return values**
	
	The function returns ``SKLOG_SUCCES`` in case of success, 
	``SKLOG_FAILURE`` in case of failure.

SKLOG_V_VerifyLogFile_uuid()
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. WARNING:: Deprecated

**Synopsis**
	
	.. c:function:: SKLOG_RETURN SKLOG_V_VerifyLogFile_uuid(SKLOG_V_Ctx *v_ctx, SKLOG_CONNECTION *c, char *logfile_id)

**Description**
	
**Return values**
	
	The function returns ``SKLOG_SUCCES`` in case of success, 
	``SKLOG_FAILURE`` in case of failure.

SKLOG_V_VerifyLogFile_v2()
^^^^^^^^^^^^^^^^^^^^^^^^^^

**Synopsis**

	.. c:function:: SKLOG_RETURN \
		SKLOG_V_VerifyLogFile_v2(SKLOG_V_Ctx *ctx, char *logfile_id, \
		SKLOG_V_DATA_TRANSFER_CB verify_cb)
		
**Description**
	
	Sends logfile verification request to T. The logfile is specified by
	``logfile_id``.
	
	For data transfering, users have to define a 
	``SKLOG_V_DATA_TRANSFER_CB`` callback (**EXPERIMENTAL**).
	
**Return values**
	
	The function returns ``SKLOG_SUCCES`` in case of success, 
	``SKLOG_FAILURE`` in case of failure.
