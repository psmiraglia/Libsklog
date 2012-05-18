********
Tutorial
********

.. highlight:: c

Preliminaries
=============

To build application that use Libsklog it's necessary to add 
``-I/urs/local/include`` to ``CFLAGS`` and ``-L/usr/local/lib 
-lsklog`` to ``LDFLAGS`` ::
	
	gcc -Wall -Werror -I/urs/local/include my_log_app.c -o my_log_app.bin -L/usr/local/lib -lsklog
	
Probably to run your application you will need to set ``LD_LIBRARY_PATH`` environment variable::

	LD_LIBRARY_PATH=/usr/local/lib ./my_log_app.bin

Using U API
===========

To use U API it's necessary to include the following libraries

.. code-block:: c

	#include <stdio.h>
	#include <sklog_u.h>
	
The first step is the initialization of the U context and then the 
initialization of a new logging session
	
.. code-block:: c

	int main ( void ) {

		SKLOG_RETURN rv = SKLOG_SUCCESS;
		SKLOG_U_Ctx *ctx = 0;
		
		char *le1 = 0;
		unsigned int le1_len = 0;
		char *le2 = 0;
		unsigned int le2_len = 0;
		
		...
		
		/* create empty context */
		
		ctx = SKLOG_U_NewCtx();
		
		if ( !ctx ) {
		
			/* manage error */
			
		}
		
		/* initialize new logging session */
		
		rv = SKLOG_U_Open(ctx, &le1, &le1_len, &le2, &le2_len)
		
		if ( rv == SKLOG_FAILURE ) {
			
			/* manage error */
		}
	
		...
		
	}
	
After that, users are ready to log their events using ``SKLOG_U_LogEvent()`` function
	
.. code-block:: c

	int main ( void ) {

		char data[BUFLEN+1] = { 0x0 };
		
		...
		
		/* create logentry */
		
		snprintf(data, BUFLEN, "This is a sample event description");
		
		rv = SKLOG_U_LogEvent(ctx, type, data, strlen(data), &le1, &le1_len);
		
		if ( rv == SKLOG_FAILURE ) {
			
			/* manage error */
		}
		
		...
		
	}
	
To terminate the logging session users have to close it and free the
context
	
.. code-block:: c

	int main ( void ) {
	
		...
		
		/* close logging session */
		
		rv = SKLOG_U_Close(ctx, &le1, &le1_len);
		
		if ( rv == SKLOG_FAILURE ) {
		
			/* manage error */
		
		}
		
		/* free memory */
		
		rv = SKLOG_U_FreeCtx(&u_ctx);
		
		if ( rv == SKLOG_FAILURE ) {
		
			/* manage error */
		
		}
		
		return 0;
	
	}

Using T API
===========

To use U API it's necessary to include the following libraries

.. code-block:: c

	#include <stdio.h>
	#include <sklog_t.h>
	
To run a simple T application users can use the function ``SKLOG_T_RunServer()``

.. code-block:: c

	#include <sklog_t.h>
	
	int main ( void ) {
	
		SKLOG_RETURN rv = SKLOG_SUCCESS;
		SKLOG_T_Ctx *ctx = 0;
		
		/* create empty context */
		
		ctx = SKLOG_T_NewCtx();
		
		if ( !ctx ) {
			
			/* manage error */
			
		} 
		
		/* initialize context */
		
		rv = SKLOG_T_InitCtx(ctx);
		
		if ( rv == SKLOG_FAILURE ) {
			
			/* manage error */
			
		}
		
		/* run T server */
		
		rv = SKLOG_T_RunServer(ctx);
		
		if ( rv == SKLOG_FAILURE ) {
			
			/* manage error */
			
		}
		
		/* free memory */
		
		rv = SKLOG_T_FreeCtx(&ctx);
		
		if ( rv == SKLOG_FAILURE ) {
			
			/* manage error */
			
		}
		
		return 0;
	}

Using V API
===========
