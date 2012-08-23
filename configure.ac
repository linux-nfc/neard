AC_PREREQ(2.60)
AC_INIT(neard, 0.6)

AM_INIT_AUTOMAKE([foreign subdir-objects color-tests])
AM_CONFIG_HEADER(config.h)

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AM_MAINTAINER_MODE

AC_PREFIX_DEFAULT(/usr/local)

if (test "${libdir}" = '${exec_prefix}/lib'); then
	libdir="${prefix}/lib"
fi

plugindir="${libdir}/near/plugins"

PKG_PROG_PKG_CONFIG

COMPILER_FLAGS

AC_LANG_C

AC_PROG_CC
AC_PROG_CC_PIE
AC_PROG_INSTALL

m4_define([_LT_AC_TAGCONFIG], [])
m4_ifdef([AC_LIBTOOL_TAGS], [AC_LIBTOOL_TAGS([])])

AC_DISABLE_STATIC
AC_PROG_LIBTOOL

AC_ARG_ENABLE(optimization, AC_HELP_STRING([--disable-optimization],
			[disable code optimization through compiler]), [
	if (test "${enableval}" = "no"); then
		CFLAGS="$CFLAGS -O0"
	fi
])

AC_ARG_ENABLE(debug, AC_HELP_STRING([--enable-debug],
			[enable compiling with debugging information]), [
	if (test "${enableval}" = "yes" &&
				test "${ac_cv_prog_cc_g}" = "yes"); then
		CFLAGS="$CFLAGS -g"
	fi
])

AC_ARG_ENABLE(pie, AC_HELP_STRING([--enable-pie],
			[enable position independent executables flag]), [
	if (test "${enableval}" = "yes" &&
				test "${ac_cv_prog_cc_pie}" = "yes"); then
		CFLAGS="$CFLAGS -fPIE"
		LDFLAGS="$LDFLAGS -pie"
	fi
])

AC_CHECK_LIB(dl, dlopen, dummy=yes,
			AC_MSG_ERROR(dynamic linking loader is required))

PKG_CHECK_MODULES(GLIB, glib-2.0 >= 2.28, dummy=yes,
				AC_MSG_ERROR(GLib >= 2.28 is required))
AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)

PKG_CHECK_MODULES(DBUS, dbus-1 >= 1.2, dummy=yes,
				AC_MSG_ERROR(D-Bus >= 1.2 is required))
AC_SUBST(DBUS_CFLAGS)
AC_SUBST(DBUS_LIBS)

PKG_CHECK_MODULES(LIBNL3, libnl-3.0 libnl-genl-3.0, [
	NETLINK_CFLAGS=${LIBNL3_CFLAGS}
	NETLINK_LIBS=${LIBNL3_LIBS}
], [
	PKG_CHECK_MODULES(LIBNL2, libnl-2.0, [
		NETLINK_CFLAGS=${LIBNL2_CFLAGS}
		NETLINK_LIBS=${LIBNL2_LIBS}
	], [
		PKG_CHECK_MODULES(LIBNL1, libnl-1, dummy=yes,
			AC_MSG_ERROR(Netlink library is required))
		AC_DEFINE(NEED_LIBNL_COMPAT, 1,
			[Define to 1 if you need libnl-1 compat functions.])
		NETLINK_CFLAGS=${LIBNL1_CFLAGS}
		NETLINK_LIBS=${LIBNL1_LIBS}
	])
])
AC_SUBST(NETLINK_CFLAGS)
AC_SUBST(NETLINK_LIBS)

AC_ARG_ENABLE(test, AC_HELP_STRING([--enable-test],
					[enable test/example scripts]),
					[enable_test=${enableval}])
AM_CONDITIONAL(TEST, test "${enable_test}" = "yes")

AC_ARG_ENABLE(tools, AC_HELP_STRING([--enable-tools],
					[enable testing tools]),
					[enable_tools=${enableval}])
AM_CONDITIONAL(TOOLS, test "${enable_tools}" = "yes")

AC_ARG_ENABLE(nfctype1, AC_HELP_STRING([--disable-nfctype1],
				[disable NFC forum type 1 tags support]),
				[enable_nfctype1=${enableval}])
AM_CONDITIONAL(NFCTYPE1, test "${enable_nfctype1}" != "no")

AC_ARG_ENABLE(nfctype2, AC_HELP_STRING([--disable-nfctype2],
				[disable NFC forum type 2 tags support]),
				[enable_nfctype2=${enableval}])
AM_CONDITIONAL(NFCTYPE2, test "${enable_nfctype2}" != "no")

AC_ARG_ENABLE(nfctype3, AC_HELP_STRING([--disable-nfctype3],
				[disable NFC forum type 3 tags support]),
				[enable_nfctype3=${enableval}])
AM_CONDITIONAL(NFCTYPE3, test "${enable_nfctype3}" != "no")

AC_ARG_ENABLE(nfctype4, AC_HELP_STRING([--disable-nfctype4],
				[disable NFC forum type 4 tags support]),
				[enable_nfctype4=${enableval}])
AM_CONDITIONAL(NFCTYPE4, test "${enable_nfctype4}" != "no")

AC_ARG_ENABLE(p2p, AC_HELP_STRING([--disable-p2p],
				[disable NFC peer to peer support]),
				[enable_p2p=${enableval}])
AM_CONDITIONAL(P2P, test "${enable_p2p}" != "no")

AC_OUTPUT(Makefile include/version.h neard.pc)
