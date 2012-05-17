AC_INIT([libsklog],[0.1],[paolo.smiraglia@polito.it])
LT_INIT
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AC_PROG_CC
AC_PROG_CC_C_O
AM_PROG_CC_C_O
AC_PROG_LIBTOOL

AC_SUBST([LIB_VERSION],[0:1:0])

dnl ********************************************************************
dnl utilities
dnl ********************************************************************

showflags() { :
	echo
	echo "CFLAGS: "$CFLAGS
	echo "LDFLAGS: "$LDFLAGS
	echo "LIBS: "$LIBS
	echo
}

dnl ********************************************************************
dnl --enable-debug
dnl ********************************************************************

AC_MSG_CHECKING([whether to build in debug mode])
AC_ARG_ENABLE(
	[debug],
    AC_HELP_STRING(
        [--enable-debug],
        [Build Libsklog with debugging features [default=no]]),[
    AC_SUBST([DBGFLAGS],["-g -O0"])
    AC_DEFINE([DO_TRACE],[1],[Build Libsklog in high verbosity mode])
    AC_MSG_RESULT(yes)],[
	AC_SUBST([DBGFLAGS],["-O3"])
	AC_MSG_RESULT(no)]
)

dnl ********************************************************************
dnl --enable-encryption
dnl ********************************************************************

AC_ARG_ENABLE(
	[encryption],
	AC_HELP_STRING(
		[--enable-encryption],
		[Build Libsklog with data encryption [default=yes]]
	),
	[enable_encryption="$enableval"],
	[enable_encryption="yes"]
)

if test "x$enable_encryption" = "xno" ; then
	AC_DEFINE([DISABLE_ENCRYPTION],[1],[Foo Desc])
fi

dnl ********************************************************************
dnl --enable-tests
dnl ********************************************************************

AC_ARG_ENABLE(
	[tests],
	AC_HELP_STRING(
		[--enable-tests],
		[Build Libsklog in CUnit teting mode [default=no]]
	),
	[enable_tests="$enableval"],
	[enable_tests="no"]
)

if test "x$enable_tests" = "xyes" ; then
	AC_DEFINE([DO_TESTS],[1],[Disable some features in order to perform unit tests])
	AM_CONDITIONAL([HAVE_TESTS],[true])
else
	AM_CONDITIONAL([HAVE_TESTS],[false])
fi

dnl ********************************************************************
dnl --enable-bindings-python
dnl ********************************************************************

AC_ARG_ENABLE(
	[bindings-python],
	AC_HELP_STRING(
		[--enable-bindings-python],
		[Build Libsklog with python bindings [default=no]]
	),
	[enable_python="$enableval"],
	[enable_python="no"]
)

if test "x$enable_python" = "xyes" ; then
	AM_PATH_PYTHON(
		[2.6],
		AC_CHECK_LIB(
			[python$PYTHON_VERSION],
			[main],[],
			AC_MSG_ERROR([libpython$PYTHON_VERSION is required for Python bindings])
		)
	)
	AC_SUBST([PY_CFLAGS],["-I/usr/include/python$PYTHON_VERSION/"])
	AC_SUBST([PY_LDFLAGS],["-lpython$PYTHON_VERSION"])
	AM_CONDITIONAL([HAVE_PYTHON],[true])
else
	AM_CONDITIONAL([HAVE_PYTHON],[false])
fi

dnl ********************************************************************
dnl --with-lumberjack
dnl ********************************************************************

AC_ARG_WITH([lumberjack],
	AC_HELP_STRING(
		[--with-lumberjack],
		[Build Libsklog with Lumberjack project capabilities [default=no]]
	),
	lumberjack="$withval",
	lumberjack="no"
)

if test "x$lumberjack" == "xyes"; then
	AC_DEFINE([UMBERLOG], [1], [Enable libumberlog features])
	AC_SUBST([UMBERLOG_CFLAGS], ["-Ilibumberlog/include"])
	AC_SUBST([UMBERLOG_LDFLAGS], ["-Llibumberlog/lib -lumberlog"])
	AM_CONDITIONAL([HAVE_UMBERLOG], [true])
else
	AM_CONDITIONAL([HAVE_UMBERLOG], [false])
fi

dnl ********************************************************************
dnl --with-storage[=type]
dnl ********************************************************************

AC_ARG_WITH([storage],
	AC_HELP_STRING(
		[--with-storage[=TYPE]],
		[Build Libsklog with storage capabilities. Supported TYPE are: sqlite, syslog, file or none. [default=sqlite]]
	),
	storage="$withval",
	storage="sqlite"
)

AM_CONDITIONAL([HAVE_STORAGE_SQLITE],[false])
AM_CONDITIONAL([HAVE_STORAGE_SYSLOG],[false])
AM_CONDITIONAL([HAVE_STORAGE_FILE],[false])
AM_CONDITIONAL([HAVE_STORAGE_NONE],[false])

case "x$storage" in
	"xsqlite")
		AC_CHECK_LIB([sqlite3],[main],[],[AC_MSG_ERROR([libsqlite3 is required from Libsklog],[exit -1])])
		AM_CONDITIONAL([HAVE_STORAGE_SQLITE],[true])
		AC_DEFINE([USE_SQLITE],[1],[Foo Desc])
		;;
	"xsyslog")
		AM_CONDITIONAL([HAVE_STORAGE_SYSLOG],[true])
		AC_DEFINE([USE_SYSLOG],[1],[Foo Desc])
		;;
	"xfile")
		AM_CONDITIONAL([HAVE_STORAGE_FILE],[true])
		AC_DEFINE([USE_FILE],[1],[Foo Desc])
		;;
	"xnone")
		AM_CONDITIONAL([HAVE_STORAGE_NONE],[true])
		AC_DEFINE([DISABLE_STORAGE],[1],[Foo Desc])
		;;
	*)
		AC_MSG_ERROR([Unsupported storage type],[exit -1])
		;;
esac

dnl ********************************************************************
dnl --with-ssl=PATH
dnl ********************************************************************

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

dnl ********************************************************************
dnl checking for libraries
dnl ********************************************************************

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
	[config],
	[main],
	[],
	AC_MSG_ERROR([libconfig is required from Libsklog])
)

AC_CHECK_LIB(
	[jansson],
	[main],
	[],
	AC_MSG_ERROR([libjansson is required from Libsklog])
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
    tests/Makefile \
    tests/CUnit/Makefile \
])

AC_OUTPUT
