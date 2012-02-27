AC_INIT([libsklog],[0.1],[paolo.smiraglia@polito.it])
LT_INIT
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AC_PROG_CC
AC_PROG_CC_C_O
AC_PROG_LIBTOOL

AC_SUBST([LIB_VERSION],[0:1:0])

dnl
dnl utilities
dnl

showflags() { :
	echo
	echo "CFLAGS: "$CFLAGS
	echo "LDFLAGS: "$LDFLAGS
	echo "LIBS: "$LIBS
	echo
}

dnl
dnl --enable-debug
dnl

AC_MSG_CHECKING([whether to build in debug mode])
AC_ARG_ENABLE(
	[debug],
    AC_HELP_STRING(
        [--enable-debug],
        [Build Libsklog with debugging features [default=no]]),[
    AC_SUBST([DBGFLAGS],["-g -O0"])
    AC_DEFINE([DO_TRACE],[],[Build Libsklog in high verbosity mode])
    AC_MSG_RESULT(yes)],[
	AC_SUBST([DBGFLAGS],["-O3"])
	AC_MSG_RESULT(no)]
)

dnl
dnl --enable-bindings-python
dnl

AC_MSG_CHECKING([whether to build with Python bindings])
AC_ARG_ENABLE(
	[bindings-python],
	AC_HELP_STRING(
		[--enable-bindings-python],
		[Build Libsklog with python bindings [default=no]]
	),[
	AC_MSG_RESULT(yes)
	AM_PATH_PYTHON(
		[2.6],
		AC_CHECK_LIB(
			[python$PYTHON_VERSION],
			[main],[
				AC_SUBST([PY_CFLAGS],["-I/usr/include/python$1/"])
				AC_SUBST([PY_LIBS],["-lpython$1"])
				AM_CONDITIONAL([PY_BINDING],[true])
			],
			AC_MSG_ERROR([libpython$PYTHON_VERSION is required for Python bindings])
		)
	)],[
	AM_CONDITIONAL([PY_BINDING],[false])
	AC_MSG_RESULT(no)]
)

dnl
dnl --with-ssl=PATH
dnl

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

AC_MSG_CHECKING([for OpenSSL directory])
AC_ARG_WITH([ssl],
    AC_HELP_STRING(
        [--with-ssl=PATH],
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
AC_SUBST([SSLDIR],"$ssldir")

dnl
dnl --without-storage-sqlite
dnl

AC_ARG_WITH([storage-sqlite],
    AC_HELP_STRING(
        [--without-storage-sqlite],
        [disable sqlite as storage driver]
    ),
    [],
    [without_storage_sqlite=no]
)

if test "x$without_storage_sqlite" == "xno"; then
    AC_CHECK_LIB([sqlite3],[sqlite3_open],[],
		AC_MSG_ERROR(libsqlite3 is required from Libsklog)
    )
    AC_SUBST([SQLITE_CFLAGS],["-DUSE_SQLITE"])
	AC_SUBST([SQLITE_LIBS],["-lsqlite3"])
else
	AC_SUBST([SQLITE_CFLAGS],[""])
	AC_SUBST([SQLITE_LIBS],[""])
fi

dnl
dnl --with-storage-file
dnl

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

dnl
dnl --with-storage-syslog
dnl

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

dnl
dnl checking for libraries
dnl

AC_CHECK_LIB(
	[ssl],
	[main],
	[],
	AC_MSG_ERROR([libssl is required from Libsklog])
)

AC_CHECK_LIB(
	[crypto],
	[main],
	[],
	AC_MSG_ERROR([libcrypto is required from Libsklog])
)

AC_CHECK_LIB(
	[uuid],
	[main],
	[],
	AC_MSG_ERROR([libuuid is required from Libsklog])
)

AC_CHECK_LIB(
	[confuse],
	[main],
	[],
	AC_MSG_ERROR([libconfuse is required from Libsklog])
)

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
    lib/Makefile \
    lib/bindings/Makefile \
])

AC_OUTPUT
