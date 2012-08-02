
AM_MAKEFLAGS = --no-print-directory

includedir = @includedir@/near

include_HEADERS = include/types.h include/log.h include/plugin.h \
			include/tag.h include/adapter.h include/ndef.h \
			include/tlv.h include/setting.h include/device.h

nodist_include_HEADERS = include/version.h

noinst_HEADERS = include/dbus.h

local_headers = $(foreach file,$(include_HEADERS) $(nodist_include_HEADERS) \
			$(noinst_HEADERS), include/near/$(notdir $(file)))

gdbus_sources = gdbus/gdbus.h gdbus/mainloop.c gdbus/watch.c \
					gdbus/object.c gdbus/polkit.c

plugin_LTLIBRARIES =

plugin_objects =

builtin_modules =
builtin_sources =
builtin_cflags =
builtin_libadd =

libexec_PROGRAMS = src/neard

src_neard_SOURCES = $(gdbus_sources) $(gweb_sources) $(builtin_sources) \
			src/main.c src/error.c src/near.h src/log.c \
			src/dbus.c src/manager.c src/adapter.c src/device.c \
			src/tag.c src/plugin.c src/netlink.c src/ndef.c \
			src/tlv.c src/bluetooth.c src/agent.c

src_neard_LDADD = $(builtin_libadd) @GLIB_LIBS@ @DBUS_LIBS@ @NETLINK_LIBS@ -lresolv -ldl

src_neard_LDFLAGS = -Wl,--export-dynamic

nodist_src_neard_SOURCES = src/builtin.h

AM_CFLAGS = @GLIB_CFLAGS@ @DBUS_CFLAGS@ @NETLINK_CFLAGS@ $(builtin_cflags) \
					-DNEAR_PLUGIN_BUILTIN \
					-DPLUGINDIR=\""$(plugindir)"\" \
					-DCONFIGDIR=\""$(configdir)\""

INCLUDES = -I$(builddir)/include -I$(builddir)/src -I$(srcdir)/gdbus

CLEANFILES = src/builtin.h $(local_headers)

plugindir = $(libdir)/near/plugins

configdir = ${sysconfdir}/neard

dist_noinst_DATA = src/main.conf

dbusdir = ${sysconfdir}/dbus-1/system.d/

dist_dbus_DATA = src/org.neard.conf

if MAINTAINER_MODE
build_plugindir = $(abs_top_srcdir)/plugins/.libs
else
build_plugindir = $(plugindir)
endif

doc_files = doc/manager-api.txt doc/tag-api.txt doc/device-api.txt doc/adapter-api.txt

EXTRA_DIST = src/genbuiltin $(doc_files)

test_scripts = test/disable-adapter test/enable-adapter test/list-adapters \
		test/dump-device test/dump-tag test/dump-record \
		test/monitor-near test/start-poll test/stop-poll test/write-tag \
		test/push-device

if TEST
testdir = $(pkglibdir)/test
test_SCRIPTS = $(test_scripts)
endif

if TOOLS
noinst_PROGRAMS = tools/snep-send

tools_snep_send_SOURCES = $(gdbus_sources) src/log.c src/dbus.c \
			src/bluetooth.c src/ndef.c tools/snep-send.c
tools_snep_send_LDADD = @GLIB_LIBS@ @DBUS_LIBS@

endif

include Makefile.plugins

EXTRA_DIST += $(test_scripts)

pkgconfigdir = $(libdir)/pkgconfig

pkgconfig_DATA = neard.pc

DISTCHECK_CONFIGURE_FLAGS = --enable-nfctype1 \
			    --enable-nfctype2 \
			    --enable-nfctype3 \
			    --enable-nfctype4 \
		            --enable-p2p

DISTCLEANFILES = $(pkgconfig_DATA)

MAINTAINERCLEANFILES = Makefile.in \
	aclocal.m4 configure config.h.in config.sub config.guess \
	ltmain.sh depcomp compile missing install-sh mkinstalldirs

src/plugin.$(OBJEXT): src/builtin.h

src/builtin.h: src/genbuiltin $(builtin_sources)
	$(AM_V_GEN)$(srcdir)/src/genbuiltin $(builtin_modules) > $@

$(src_neard_OBJECTS) $(plugin_objects): $(local_headers)

include/near/version.h: include/version.h
	$(AM_V_at)$(MKDIR_P) include/near
	$(AM_V_GEN)$(LN_S) $(abs_top_builddir)/$< $@

include/near/%.h: include/%.h
	$(AM_V_at)$(MKDIR_P) include/near
	$(AM_V_GEN)$(LN_S) $(abs_top_srcdir)/$< $@

clean-local:
	@$(RM) -rf include/near
