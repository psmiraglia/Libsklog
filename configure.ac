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

AC_ARG_ENABLE([trace],
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

AC_ARG_ENABLE([notify],
    AS_HELP_STRING(
        [--enable-notify],
        [Enable notify messages for libsklog library [default=no]]
    ),
    [enable_notify="yes"],
    [enable_notify="no"]
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
# enable Debug
#----------------------------------------------------------------------

AC_ARG_ENABLE([debug],
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
# with SSL
#----------------------------------------------------------------------
checkssldir() { :
    if test -f "$1/include/openssl/ssl.h"
    then
        ssldir="$1"
        return 0
    fi
    if test -f "$1/include/ssl.h"
    then
        ssldir="$1"
        return 0
    fi
    return 1
}

AC_MSG_CHECKING(
    [for OpenSSL directory]
)

AC_ARG_WITH(
    ssl,
    AC_HELP_STRING(
        [--with-ssl=DIR],
        [location of installed OpenSSL libraries/include files]
    ),
    [checkssldir "$withval"],
    [
        for maindir in /usr /usr/local /opt; do
            for dir in $maindir $maindir/openssl $maindir/ssl; do
               checkssldir $dir && break 2
            done
        done
    ]
)

if test -z "$ssldir"
then AC_MSG_RESULT([Not found])
    echo -e "\nCouldn't find your OpenSSL dir\n"
    echo -e "Use --with-ssl option to fix this problem\n"
    exit 1
fi
AC_MSG_RESULT([$ssldir])

# add SSL include and libraries
CFLAGS="$CFLAGS -I$ssldir/include"
LIBS="$LIBS -L$ssldir/lib -lcrypto -lssl"

#----------------------------------------------------------------------
# without STORAGE SQLite
#----------------------------------------------------------------------
AC_ARG_WITH([storage-sqlite],
    AC_HELP_STRING(
        [--without-storage-sqlite],
        [disable sqlite as storage driver]
    ),
    [],
    [without_storage_sqlite=no]
)

if test "x$without_storage_sqlite" == "xno"; then
    CFLAGS="$CFLAGS -DUSE_SQLITE"
    LIBS="$LIBS -lsqlite3"
    AC_CHECK_LIB([sqlite3],[sqlite3_open])
fi

#----------------------------------------------------------------------
# with STORAGE File
#----------------------------------------------------------------------
AC_ARG_WITH([storage-file],
    AC_HELP_STRING(
        [--with-storage-file],
        [set file as storage driver]
    ),
    [],
    [with_storage_file=no]
)

if test "x$with_storage_file" != "xno"; then
    CFLAGS="$CFLAGS -DUSE_FILE"
fi

#----------------------------------------------------------------------
# with STORAGE Syslog
#----------------------------------------------------------------------
AC_ARG_WITH([storage-syslog],
    AC_HELP_STRING(
        [--with-storage-syslog],
        [send logentry to syslog daemon]
    ),
    [],
    [with_storage_syslog=no]
)

if test "x$with_storage_syslog" != "xno"; then
    CFLAGS="$CFLAGS -DUSE_SYSLOG"
fi

#----------------------------------------------------------------------
# checking for libraries
#----------------------------------------------------------------------
#AC_CHECK_LIB([crypto],[EVP_MD_CTX_init])
#AC_CHECK_LIB([ssl],[SSL_CTX_new])
AC_CHECK_LIB([confuse],[cfg_init])
AC_CHECK_LIB([uuid],[uuid_generate_random])

#----------------------------------------------------------------------
#----------------------------------------------------------------------

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([\
    Makefile \
    apps/Makefile \
    docs/Makefile \
    docs/certs/Makefile \
    docs/config/Makefile \
    docs/sql/Makefile \
    docs/rsyslog.d/Makefile \
    include/Makefile \
    lib/Makefile\
])

AC_OUTPUT

