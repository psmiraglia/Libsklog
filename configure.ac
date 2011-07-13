AC_INIT([libsklog],[0.1],[paolo.smiraglia@polito.it])
LT_INIT
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AC_PROG_CC
AC_PROG_CC_C_O
AC_PROG_LIBTOOL

AC_SUBST([LIB_VERSION],[0:1:0])

#----------------------------------------------------------------------
# enable DO_TRACE
#----------------------------------------------------------------------

AC_ARG_ENABLE(
    trace,
    AS_HELP_STRING(
        [--enable-trace],
        [Enable high verbosity mode for libsklog library [default=no]]
    ),
    [enable_trace="yes"],
    [enable_trace="no"]
)

AC_MSG_CHECKING(
    [whether to build in high verbosity mode]
)

AC_MSG_RESULT(${enable_trace})

if test "x${enable_trace}" = "xyes" ; then
    AC_DEFINE(
        [DO_TRACE],
        [],
        [Enable high verbosity mode for libsklog library]
    )
fi

#----------------------------------------------------------------------
# enable DO_NOTIFY
#----------------------------------------------------------------------

AC_ARG_ENABLE(
    notify,
    AS_HELP_STRING(
        [--enable-notify],
        [Enable notify messages for libsklog library [default=no]]
    ),
    [enable_trace="yes"],
    [enable_trace="no"]
)

AC_MSG_CHECKING(
    [whether to build with notify messages]
)

AC_MSG_RESULT(${enable_notify})

if test "x${enable_notify}" = "xyes" ; then
    AC_DEFINE(
        [DO_NOTIFY],
        [],
        [Enable notify messages for libsklog library]
    )
fi

#----------------------------------------------------------------------
# enable USE_QUOTE
#----------------------------------------------------------------------

#AC_ARG_ENABLE(
#    quote,
#    AS_HELP_STRING(
#        [--enable-quote],
#        [Enable the usage of TPM_Quote in log entry computation 
#            [default=no]]),
#    [enable_quote=yes],
#    [enable_quote=no]
#)

#AC_MSG_CHECKING(
#    [whether to build with TPM_Quote support]
#)

#AC_MSG_RESULT(${enable_quote})

#if test "x${enable_quote}" = "xyes" ; then
#    AC_DEFINE(
#        [USE_QUOTE],
#        [],
#        [Enable the usage of TPM_Quote in log entry computation]
#    )
#    AC_CHECK_LIB(
#        [tpa],
#        [TpaHL_CTX_allocate]
#    )
#fi

#----------------------------------------------------------------------
# enable Debug
#----------------------------------------------------------------------

AC_ARG_ENABLE(
    debug,
    AC_HELP_STRING(
        [--enable-debug],
        [enable debug support [default=no]]),
    [enable_debug="yes"],
    [enable_debug="no"]
)

AC_MSG_CHECKING(
    [whether to build in debug mode]
)

AC_MSG_RESULT(${enable_debug})

if test "x${enable_debug}" = "xyes" ; then
    AC_DEFINE(
        CMAID_ENABLE_DEBUG,
        1,
        [Enable debug support]
    )
    
    CFLAGS="$CFLAGS -g"
fi

#----------------------------------------------------------------------
# checking for libraries
#----------------------------------------------------------------------
AC_CHECK_LIB([crypto],[EVP_MD_CTX_init])
AC_CHECK_LIB([ssl],[SSL_CTX_new])
AC_CHECK_LIB([confuse],[cfg_init])
AC_CHECK_LIB([uuid],[uuid_generate_random])
AC_CHECK_LIB([sqlite3],[sqlite3_open])

#----------------------------------------------------------------------
#----------------------------------------------------------------------

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile lib/Makefile apps/Makefile include/Makefile])

AC_OUTPUT

