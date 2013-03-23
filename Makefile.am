
AM_MAKEFLAGS = --no-print-directory

includedir = @includedir@/near

include_HEADERS = include/types.h include/log.h include/plugin.h \
			include/tag.h include/adapter.h include/ndef.h \
			include/tlv.h include/setting.h include/device.h \
			include/nfc_copy.h include/snep.h

nodist_include_HEADERS = include/version.h

noinst_HEADERS = include/dbus.h

local_headers = $(foreach file,$(include_HEADERS) $(nodist_include_HEADERS) \
			$(noinst_HEADERS), include/near/$(notdir $(file)))

gdbus_sources = gdbus/gdbus.h gdbus/mainloop.c gdbus/watch.c \
				gdbus/object.c gdbus/client.c gdbus/polkit.c

plugin_LTLIBRARIES =

plugin_objects =

unit_objects =

builtin_modules =
builtin_sources =
builtin_cflags =
builtin_libadd =

bin_PROGRAMS =

libexecdir = @libexecdir@/nfc
libexec_PROGRAMS = src/neard

src_neard_SOURCES = $(gdbus_sources) $(gweb_sources) $(builtin_sources) \
			src/main.c src/error.c src/near.h src/log.c \
			src/dbus.c src/manager.c src/adapter.c src/device.c \
			src/tag.c src/plugin.c src/netlink.c src/ndef.c \
			src/tlv.c src/bluetooth.c src/agent.c src/snep.c

src_neard_LDADD = $(builtin_libadd) @GLIB_LIBS@ @DBUS_LIBS@ @NETLINK_LIBS@ -ldl

src_neard_LDFLAGS = -Wl,--export-dynamic

nodist_src_neard_SOURCES = src/builtin.h

AM_CFLAGS = @GLIB_CFLAGS@ @DBUS_CFLAGS@ @NETLINK_CFLAGS@ $(builtin_cflags) \
					-DNEAR_PLUGIN_BUILTIN \
					-DPLUGINDIR=\""$(plugindir)"\" \
					-DCONFIGDIR=\""$(configdir)\""

AM_CPPFLAGS = -I$(builddir)/include -I$(builddir)/src -I$(srcdir)/gdbus

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

doc_files = doc/manager-api.txt doc/tag-api.txt doc/device-api.txt \
		doc/adapter-api.txt doc/agent-api.txt

EXTRA_DIST = src/genbuiltin $(doc_files)

dist_man_MANS = doc/neard.8 doc/neard.conf.5 doc/nfctool.1

test_scripts = test/disable-adapter test/enable-adapter test/list-adapters \
		test/dump-device test/dump-tag test/dump-record \
		test/monitor-near test/start-poll test/stop-poll test/write-tag \
		test/push-device test/bt-handover test/handover-agent

if TEST
testdir = $(pkglibdir)/test
test_SCRIPTS = $(test_scripts)
endif

if TOOLS
bin_PROGRAMS += tools/nfctool/nfctool

noinst_PROGRAMS = tools/snep-send

tools_snep_send_SOURCES = $(gdbus_sources) src/log.c src/dbus.c \
					src/bluetooth.c src/ndef.c \
					tools/snep-send.c src/agent.c
tools_snep_send_LDADD = @GLIB_LIBS@ @DBUS_LIBS@

tools_nfctool_nfctool_SOURCES = tools/nfctool/main.c \
					tools/nfctool/nfctool.h \
					tools/nfctool/adapter.h \
					tools/nfctool/adapter.c \
					tools/nfctool/netlink.h \
					tools/nfctool/netlink.c \
					tools/nfctool/sniffer.h \
					tools/nfctool/sniffer.c \
					tools/nfctool/llcp-decode.h \
					tools/nfctool/llcp-decode.c

tools_nfctool_nfctool_LDADD = @GLIB_LIBS@ @NETLINK_LIBS@

unit_tests = unit/test-ndef-parse unit/test-ndef-build unit/test-snep-read

unit_test_ndef_parse_SOURCES = $(gdbus_sources) src/log.c src/dbus.c \
					src/agent.c src/bluetooth.c \
					src/ndef.c unit/test-ndef-parse.c
unit_test_ndef_parse_LDADD = @GLIB_LIBS@ @DBUS_LIBS@

unit_test_ndef_build_SOURCES = $(gdbus_sources) src/log.c src/dbus.c \
					src/agent.c src/bluetooth.c \
					src/ndef.c unit/test-ndef-build.c
unit_test_ndef_build_LDADD = @GLIB_LIBS@ @DBUS_LIBS@

unit_test_snep_read_SOURCES = $(gdbus_sources) src/log.c src/dbus.c \
					src/agent.c src/bluetooth.c \
					src/ndef.c src/snep.c \
					unit/test-snep-read.c unit/test-utils.c \
					unit/test-utils.h
unit_test_snep_read_LDADD = @GLIB_LIBS@ @DBUS_LIBS@

noinst_PROGRAMS += $(unit_tests)

TESTS = $(unit_tests)

endif

include Makefile.plugins

EXTRA_DIST += $(test_scripts)

pkgconfigdir = $(libdir)/pkgconfig

pkgconfig_DATA = neard.pc

DISTCHECK_CONFIGURE_FLAGS = --enable-tools

DISTCLEANFILES = $(pkgconfig_DATA)

MAINTAINERCLEANFILES = Makefile.in \
	aclocal.m4 configure config.h.in config.sub config.guess \
	ltmain.sh depcomp compile missing install-sh mkinstalldirs

src/plugin.$(OBJEXT): src/builtin.h

src/builtin.h: src/genbuiltin $(builtin_sources)
	$(AM_V_GEN)$(srcdir)/src/genbuiltin $(builtin_modules) > $@

$(src_neard_OBJECTS) $(tools_nfctool_nfctool_OBJECTS) $(plugin_objects): $(local_headers)

include/near/version.h: include/version.h
	$(AM_V_at)$(MKDIR_P) include/near
	$(AM_V_GEN)$(LN_S) $(abs_top_builddir)/$< $@

include/near/%.h: include/%.h
	$(AM_V_at)$(MKDIR_P) include/near
	$(AM_V_GEN)$(LN_S) $(abs_top_srcdir)/$< $@

clean-local:
	@$(RM) -rf include/near
