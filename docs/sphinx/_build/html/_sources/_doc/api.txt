**************
API References
**************

.. highlight:: c

Preliminaries
=============

All declarations are in ``sklog_u.h``, ``sklog_t.h`` and 
``sklog_v.h``, so it's enough to include one or more of these libraries
in each source file.

::

   #include <sklog_u.h> // to access U API
   #include <sklog_t.h> // to access T API
   #include <sklog_v.h> // to access V API



Global types
============

.. c:type:: SKLOG_RETURN

.. code-block:: c

	#define SKLOG_SUCCESS 1
	#define SKLOG_FAILURE !SKLOG_SUCCESS
	
	typedef int SKLOG_RETURN;

.. c:type:: SKLOG_DATA_TYPE

.. code-block:: c

	typedef enum sklog_data_type SKLOG_DATA_TYPE;
	
	enum sklog_data_type {
	    LogfileInitializationType,
	    ResponseMessageType,
	    AbnormalCloseType,
	    NormalCloseMessage,
	    Undefined
	};
	
.. c:type:: SKLOG_CONNECTION

.. code-block:: c

	typedef struct sklog_connection SKLOG_CONNECTION;
	
	struct sklog_connection {
	    SSL		*ssl;
	    SSL_CTX	*ssl_ctx;
	
	    BIO		*bio;
	    BIO		*ssl_bio;
	    BIO		*sock_bio;
	
	    int		lsock;
	    int		csock;
	};

SKLOG_U APIs
============

Types
-----

.. c:type:: SKLOG_U_Ctx

.. code-block:: c

	typedef struct sklog_u_ctx SKLOG_U_Ctx;

	struct sklog_u_ctx {
	
	    int context_state;
	    int logging_session_mgmt;
	
	    /* u-node informtion */
	    
	    char            u_id[HOST_NAME_MAX+1];
	    unsigned int    u_id_len;
	
	    int             u_timeout;
	    unsigned long	u_expiration;
	
	    X509            *u_cert;
	    char            u_cert_file_path[MAX_FILE_PATH_LEN];
	    
	    EVP_PKEY        *u_privkey;
	    char            u_privkey_file_path[MAX_FILE_PATH_LEN];
	
	    /* t-node information */
	    
	    X509            *t_cert;
	    char            t_cert_file_path[MAX_FILE_PATH_LEN];
	
	    char            t_address[512];
	    short int       t_port;
	
	    /* logging session information */
	    
	    int             logfile_size;
	    int             logfile_counter;
	    uuid_t          logfile_id;
	
	    unsigned char   session_key[SKLOG_SESSION_KEY_LEN];
	    unsigned char   auth_key[SKLOG_AUTH_KEY_LEN];
	    unsigned char   last_hash_chain[SKLOG_HASH_CHAIN_LEN];
	
	    unsigned char   x0_hash[SHA256_LEN];
	
	    /* log-entries storage driver */
	    
	    SKLOG_U_STORAGE_DRIVER *lsdriver;
	
	};

.. c:type:: SKLOG_U_STORAGE_DRIVER

.. code-block:: c

	typedef struct sklog_u_storage_driver SKLOG_U_STORAGE_DRIVER;
	
	struct sklog_u_storage_driver {
	
	    SKLOG_RETURN (*store_logentry) (uuid_t, SKLOG_DATA_TYPE, unsigned char *, unsigned int, unsigned char *, unsigned char *);
			
	    SKLOG_RETURN (*flush_logfile) (uuid_t, unsigned long, SKLOG_CONNECTION *);
			
	    SKLOG_RETURN (*init_logfile) (uuid_t, unsigned long);
	};

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
		unsigned char **buf1, unsigned int *buf1_len, char **buf2, \
		unsigned int *buf2_len)

**Description**
	
	Executes the first step of the logging session initialization phase.
	``buf1`` buffer, which is ``buf1_len`` bytes length, will contains
	the request message (M0). ``buf2`` buffer will contains the first
	logentry of a new log file and will be ``buf2_len`` bytes length. 
	
	
**Return values**
	
	The function returns ``SKLOG_SUCCES`` in case of success, 
	``SKLOG_FAILURE`` in case of failure.

SKLOG_U_Open_M1()
^^^^^^^^^^^^^^^^^

**Synopsis**

	.. c:function:: SKLOG_RETURN SKLOG_U_Open_M1(SKLOG_U_Ctx *ctx, \
		unsigned char *buf1,	unsigned int buf1_len, char **buf2, \
		unsigned int *buf2_len)

**Description**
	
	Executes the second step of the logging session initialization
	phase. ``buf1``, that is ``buf1_len`` bytes length, will contains
	the response message (M1). ``buf2`` buffer will contains the second
	logentry of a new log file and will be ``buf2_len`` bytes length.
	
	
**Return values**
	
	The function returns ``SKLOG_SUCCES`` in case of success, 
	``SKLOG_FAILURE`` in case of failure.

SKLOG_U_LogEvent()
^^^^^^^^^^^^^^^^^^

**Synopsis**

	.. c:function:: SKLOG_RETURN SKLOG_U_LogEvent(SKLOG_U_Ctx *u_ctx, \
		SKLOG_DATA_TYPE type, char *data, unsigned int data_len, \
		char **le, unsigned int *le_len)
	
**Description**
	
	Log an event of type ``type`` described in the buffer ``data`` of 
	``data_len`` bytes and put the generated logenrty in ``le`` 
	buffer and its length in ``ls_len``.
	
**Notes**

	The logentry can assume two different format. The default one is ::
	
		[Undefined]-[/uD/HihG8/UpeoQTvX25XnmCEhhVXUSIlJ1xVaaE+rIz48ttdcazL+r/fVJ2kysT\]-[N759xRQyV2LBH5QEqWR0EGoYGlPCszzsKafBhgo+FgQ=]-[hfAKmuNyGf1I1SwnNfsIY8sTePhMTdhqx04OP42vmL8=]
	
	
	Another supported format is a json structure which is generated using
	the API provided by ``libumberlog`` library (`Lumberjack Project`_).
	
	.. code-block:: javascript
		
		{
			"msg":"/uD/HihG8/UpeoQTvX25XnmCEhhVXUSIlJ1xVaaE+rIz48ttdcazL+r/fVJ2kysT\",
			"sklog_type":"0x4",
			"sklog_hash":"N759xRQyV2LBH5QEqWR0EGoYGlPCszzsKafBhgo+FgQ=",
			"sklog_hmac":"hfAKmuNyGf1I1SwnNfsIY8sTePhMTdhqx04OP42vmL8=",
			"sklog_session":"6921523a-a010-11e1-84ef-0025b345ca14",
			"pid":"0",
			"facility":"kern",
			"priority":"notice",
			"program":"(null)",
			"uid":"0",
			"gid":"0",
			"host":"",
			"timestamp":"2012-05-17T13:07:34.981355492+0200"
		}
	
	To enable this format use the ``--with-lumberjack`` option when run
	``./configure`` script. ::
		
		./configure --enable-debug --with-lumberjack
	
**Return values**
	
	The function returns ``SKLOG_SUCCES`` in case of success, 
	``SKLOG_FAILURE`` in case of failure.

SKLOG_U_Close()
^^^^^^^^^^^^^^^

**Synopsis**

	.. c:function:: SKLOG_RETURN SKLOG_U_Close(SKLOG_U_Ctx *u_ctx, char **le, unsigned int *le_len)

**Description**
	
	Terminate an already opened logging session. This phase 
	generates the last logentry of the session. Such as logentry will
	be contained in ``le`` buffer that will be ``le_len`` bytes length.
	
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

.. code-block:: c

	typedef struct sklog_t_ctx SKLOG_T_Ctx;
	
	struct sklog_t_ctx {
	
		char		t_id[HOST_NAME_MAX+1];
		int			t_id_len;
		
		char		t_address[HOST_NAME_MAX+1];
		short int	t_port;
		
		X509		*t_cert;
		char		t_cert_file_path[MAX_FILE_PATH_LEN];
		
		EVP_PKEY	*t_privkey;
		char		t_privkey_file_path[MAX_FILE_PATH_LEN];
		
		SKLOG_T_STORAGE_DRIVER	*lsdriver;
		
	};
	
	
.. c:type:: SKLOG_T_STORAGE_DRIVER

.. code-block:: c

	typedef struct sklog_t_storage_driver SKLOG_T_STORAGE_DRIVER;
	
	struct sklog_t_storage_driver {
		SKLOG_RETURN (*store_authkey) (char*, uuid_t, unsigned char*);
		SKLOG_RETURN (*store_m0_msg) (char*, uuid_t, unsigned char*, unsigned int);
		SKLOG_RETURN (*store_logentry) (unsigned char*, unsigned int);
		SKLOG_RETURN (*retrieve_logfiles) (unsigned char **, unsigned int *);
		SKLOG_RETURN (*verify_logfile) (unsigned char *);
	};

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

	.. c:function:: SKLOG_RETURN SKLOG_T_InitCtx(SKLOG_T_Ctx *t_ctx)

**Description**

	Initialize the T API context ``t_ctx`` by reading the configuration
	file ``libsklog-t.conf``.
	
**Return values**
	
	The function returns ``SKLOG_SUCCES`` in case of success, 
	``SKLOG_FAILURE`` in case of failure.
	
SKLOG_T_ManageLoggingSessionInit()
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Synopsis**

	.. c:function:: SKLOG_RETURN SKLOG_T_ManageLoggingSessionInit(SKLOG_T_Ctx *t_ctx, \
		unsigned char *m0, unsigned int m0_len, char *u_address, \
		unsigned char **m1, unsigned int *m1_len)
	
**Description**
	
	Manage the logging session initialization requests coming from a
	client who has ``u_address`` IP address. The buffer ``m0``, that
	will be ``m0_len`` bytes len, will contains the request data.
	
**Return values**	
	
	The function returns ``SKLOG_SUCCES`` in case of success, 
	``SKLOG_FAILURE`` in case of failure.

SKLOG_T_ManageLogfileUpload()
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Synopsis**
	
	.. c:function:: SKLOG_RETURN SKLOG_T_ManageLogfileUpload(SKLOG_T_Ctx *t_ctx, \
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
		SKLOG_T_ManageLogfileRetrieve(SKLOG_T_Ctx *t_ctx, \
		char *logfile_list[], unsigned int *logfile_list_len)

**Description**
	
	Manages the logfile retrieve requests. The array ``logfile_list``,
	that will be composed by ``logfile_list_len`` elements, 
	will contains a list of logging session ids.
	
**Return values**
	
	The function returns ``SKLOG_SUCCES`` in case of success, 
	``SKLOG_FAILURE`` in case of failure.
	
SKLOG_T_ManageLogfileVerify()
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Synopsis**

	.. c:function:: SKLOG_RETURN \
		SKLOG_T_ManageLogfileVerify(SKLOG_T_Ctx *t_ctx, \
		char *logfile_id)
	
**Description**

	Manages the logfile verification requests. ``logfile_id`` specifies
	what is logfile that will be verified.
	
**Return values**
	
	The function returns ``SKLOG_SUCCES`` in case of success, 
	``SKLOG_FAILURE`` in case of failure.

SKLOG_T_FreeCtx()
^^^^^^^^^^^^^^^^^

**Synopsis**

	.. c:function:: SKLOG_RETURN SKLOG_T_FreeCtx(SKLOG_T_Ctx **t_ctx)

**Description**

	Free the memory allocated for ``t_ctx`` structure.
	
**Return values**
	
	The function returns ``SKLOG_SUCCES`` in case of success, 
	``SKLOG_FAILURE`` in case of failure.

SKLOG_T_RunServer()
^^^^^^^^^^^^^^^^^^^

**Synopsis**

	.. c:function:: SKLOG_RETURN SKLOG_T_RunServer(SKLOG_T_Ctx *t_ctx)

**Description**
	
	Implements a simple T application.
	
**Return values**
	
	The function returns ``SKLOG_SUCCES`` in case of success, 
	``SKLOG_FAILURE`` in case of failure.

SKLOG_V APIs
============

.. WARNING:: The SKLOG_V API needs to be revised

Types
-----

.. c:type:: SKLOG_V_Ctx

Functions
---------

SKLOG_V_NewCtx()
^^^^^^^^^^^^^^^^

**Synopsis**
	
	.. c:function:: SKLOG_V_Ctx* SKLOG_V_NewCtx(void)

**Description**
	
	TODO
	
**Return values**
	
	The function returns a valid pointer to a ``SKLOG_V_Ctx`` 
	structure in case of success, ``NULL`` in case of error.

SKLOG_V_InitCtx()
^^^^^^^^^^^^^^^^^

**Synopsis**

	.. c:function:: SKLOG_RETURN SKLOG_V_InitCtx(SKLOG_V_Ctx *ctx)

**Description**
	
	TODO
	
**Return values**
	
	The function returns ``SKLOG_SUCCES`` in case of success, 
	``SKLOG_FAILURE`` in case of failure.

SKLOG_V_FreeCtx()
^^^^^^^^^^^^^^^^^

**Synopsis**
	
	.. c:function:: SKLOG_RETURN SKLOG_V_FreeCtx(SKLOG_V_Ctx **ctx)

**Description**
	
	TODO
	
**Return values**
	
	The function returns ``SKLOG_SUCCES`` in case of success, 
	``SKLOG_FAILURE`` in case of failure.

SKLOG_V_RetrieveLogFiles()
^^^^^^^^^^^^^^^^^^^^^^^^^^

**Synopsis**
	
	.. c:function:: SKLOG_RETURN SKLOG_V_RetrieveLogFiles(SKLOG_V_Ctx *v_ctx, SKLOG_CONNECTION *c)

**Description**
	
	TODO
	
**Return values**
	
	The function returns ``SKLOG_SUCCES`` in case of success, 
	``SKLOG_FAILURE`` in case of failure.

SKLOG_V_VerifyLogFile()
^^^^^^^^^^^^^^^^^^^^^^^

**Synopsis**
	
	.. c:function:: SKLOG_RETURN SKLOG_V_VerifyLogFile(SKLOG_V_Ctx *v_ctx, SKLOG_CONNECTION *c, unsigned int logfile_id)

**Description**
	
	TODO
	
**Return values**
	
	The function returns ``SKLOG_SUCCES`` in case of success, 
	``SKLOG_FAILURE`` in case of failure.

SKLOG_V_VerifyLogFile_uuid()
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Synopsis**
	
	.. c:function:: SKLOG_RETURN SKLOG_V_VerifyLogFile_uuid(SKLOG_V_Ctx *v_ctx, SKLOG_CONNECTION *c, char *logfile_id)

**Description**
	
	TODO
	
**Return values**
	
	The function returns ``SKLOG_SUCCES`` in case of success, 
	``SKLOG_FAILURE`` in case of failure.

.. _`Lumberjack Project`: https://fedorahosted.org/lumberjack/
