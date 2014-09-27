
ACLOCAL_AMFLAGS = -I m4

AM_MAKEFLAGS = --no-print-directory

pkgincludedir = ${includedir}/near

pkginclude_HEADERS = include/types.h include/log.h include/plugin.h \
			include/tag.h include/adapter.h include/ndef.h \
			include/tlv.h include/setting.h include/device.h \
			include/nfc_copy.h include/snep.h

nodist_include_HEADERS = include/version.h

noinst_HEADERS = include/dbus.h

local_headers = $(foreach file,$(pkginclude_HEADERS) $(nodist_include_HEADERS) \
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

pkglibexecdir = ${libexecdir}/nfc
pkglibexec_PROGRAMS = src/neard

src_neard_SOURCES = $(gdbus_sources) $(gweb_sources) $(builtin_sources) \
			src/main.c src/error.c src/near.h src/log.c \
			src/dbus.c src/manager.c src/adapter.c src/device.c \
			src/tag.c src/plugin.c src/netlink.c src/ndef.c \
			src/tlv.c src/bluetooth.c src/agent.c src/snep.c

src_neard_LDADD = $(builtin_libadd) ${GLIB_LIBS} ${DBUS_LIBS} ${NETLINK_LIBS} -ldl

src_neard_LDFLAGS = -Wl,--export-dynamic

src_neard_DEPENDENCIES= src/neard.service

BUILT_SOURCES = src/builtin.h

AM_CPPFLAGS = ${GLIB_CFLAGS} ${DBUS_CFLAGS} ${NETLINK_CFLAGS} \
		-DNEAR_PLUGIN_BUILTIN -DPLUGINDIR=\""$(plugindir)"\" \
		-DCONFIGDIR=\""$(configdir)\"" \
		-I$(builddir)/include -I$(builddir)/src -I$(srcdir)/gdbus

AM_CFLAGS = ${builtin_cflags} -I$(builddir)/include -I$(builddir)/src -I$(srcdir)/gdbus

if SE

se_plugin_LTLIBRARIES =

se_plugin_objects =

builtin_se_modules =
builtin_se_sources =
builtin_se_libadd =
builtin_se_cflags =

pkglibexec_PROGRAMS += se/seeld

se_seeld_SOURCES = $(gdbus_sources) $(builtin_se_sources) \
			src/log.c src/dbus.c src/error.c src/plugin.c \
			se/main.c se/seel.h se/manager.c se/manager.h \
			se/se.c se/driver.c se/driver.h se/apdu.c \
			se/channel.c se/ace.c

se_seeld_LDADD = $(builtin_se_libadd) @GLIB_LIBS@ @DBUS_LIBS@ -ldl

se_seeld_LDFLAGS = -Wl,--export-dynamic

BUILT_SOURCES += se/builtin.h
endif

src_neard_CFLAGS = ${builtin_cflags} -I$(builddir)/include -I$(builddir)/src -I$(srcdir)/gdbus

src_neard_CPPFLAGS = ${GLIB_CFLAGS} ${DBUS_CFLAGS} ${NETLINK_CFLAGS} \
			-DNEAR_PLUGIN_BUILTIN \
			-DPLUGINDIR=\""$(plugindir)"\" \
			-DCONFIGDIR=\""$(configdir)\"" \
			-I$(builddir)/include -I$(builddir)/src -I$(srcdir)/gdbus

if SE
src_seeld_CFLAGS = ${builtin_se_cflags} -I$(builddir)/include -I$(builddir)/src -I$(srcdir)/gdbus

se_seeld_CPPFLAGS = ${GLIB_CFLAGS} ${DBUS_CFLAGS} ${NETLINK_CFLAGS} \
					-DNEAR_PLUGIN_BUILTIN \
					-DPLUGINDIR=\""$(build_se_plugindir)"\" \
					-DCONFIGDIR=\""$(configdir)\"" \
					-I$(builddir)/se
endif

CLEANFILES = src/builtin.h se/builtin.h $(local_headers)

configdir = ${sysconfdir}/neard

dist_noinst_DATA = src/main.conf

dbusdir = ${sysconfdir}/dbus-1/system.d/

dist_dbus_DATA = src/org.neard.conf

if MAINTAINER_MODE

if SE
build_se_plugindir = $(abs_top_srcdir)/se/plugins/.libs
endif

build_plugindir = $(abs_top_srcdir)/plugins/.libs

else

if SE
build_se_plugindir = $(se_plugindir)
endif

build_plugindir = $(plugindir)
endif

doc_files = doc/tag-api.txt doc/device-api.txt doc/adapter-api.txt \
		doc/agent-api.txt doc/phdc-api.txt \
		doc/secureelement-api.txt doc/se-manager-api.txt

EXTRA_DIST = src/genbuiltin $(doc_files)

dist_man_MANS = doc/neard.8 doc/neard.conf.5 doc/nfctool.1

test_scripts = test/test-adapter test/test-device \
		test/test-tag test/monitor-near test/bt-handover \
		test/handover-agent test/phdc-simple-manager \
		test/neardutils.py

if SYSTEMD
systemdsystemunitdir = ${SYSTEMD_SYSTEMUNITDIR}
systemdsystemunit_DATA = src/neard.service
endif

EXTRA_DIST += src/neard.service.in
CLEANFILES += src/neard.service

if TEST
testdir = $(pkglibdir)/test
test_SCRIPTS = $(test_scripts)
endif

if TOOLS
bin_PROGRAMS += tools/nfctool/nfctool

noinst_PROGRAMS = tools/snep-send

tools_snep_send_SOURCES = $(gdbus_sources) src/log.c src/dbus.c \
					src/bluetooth.c src/ndef.c \
					tools/snep-send.c src/error.c \
					src/agent.c
tools_snep_send_LDADD = ${GLIB_LIBS} ${DBUS_LIBS}

tools_nfctool_nfctool_SOURCES = tools/nfctool/main.c \
					tools/nfctool/nfctool.h \
					tools/nfctool/adapter.h \
					tools/nfctool/adapter.c \
					tools/nfctool/netlink.h \
					tools/nfctool/netlink.c \
					tools/nfctool/sniffer.h \
					tools/nfctool/sniffer.c \
					tools/nfctool/llcp-decode.h \
					tools/nfctool/llcp-decode.c \
					tools/nfctool/snep-decode.h \
					tools/nfctool/snep-decode.c \
					tools/nfctool/ndef-decode.h \
					tools/nfctool/ndef-decode.c \
					tools/nfctool/display.h \
					tools/nfctool/display.c

tools_nfctool_nfctool_LDADD = ${GLIB_LIBS} ${NETLINK_LIBS}
endif

tools_nfctool_nfctool_CPPFLAGS = ${GLIB_CFLAGS} ${DBUS_CFLAGS} ${NETLINK_CFLAGS} \
			-DNEAR_PLUGIN_BUILTIN \
			-DPLUGINDIR=\""$(plugindir)"\" \
			-DCONFIGDIR=\""$(configdir)\"" \
			-I$(builddir)/include -I$(builddir)/src -I$(srcdir)/gdbus

unit_tests = unit/test-ndef-parse unit/test-ndef-build unit/test-snep-read

unit_test_ndef_parse_SOURCES = $(gdbus_sources) src/log.c src/dbus.c \
					src/error.c src/agent.c \
					src/bluetooth.c src/ndef.c \
					unit/test-ndef-parse.c
unit_test_ndef_parse_LDADD = ${GLIB_LIBS} ${DBUS_LIBS}

unit_test_ndef_build_SOURCES = $(gdbus_sources) src/log.c src/dbus.c \
					src/error.c src/agent.c \
					src/bluetooth.c src/ndef.c \
					unit/test-ndef-build.c
unit_test_ndef_build_LDADD = ${GLIB_LIBS} ${DBUS_LIBS}

unit_test_snep_read_SOURCES = $(gdbus_sources) src/log.c src/dbus.c \
					src/error.c src/agent.c \
					src/bluetooth.c src/ndef.c src/snep.c \
					unit/test-snep-read.c unit/test-utils.c \
					unit/test-utils.h
unit_test_snep_read_LDADD = ${GLIB_LIBS} ${DBUS_LIBS}

check_PROGRAMS = $(unit_tests)

TESTS = $(unit_tests)

include Makefile.plugins

EXTRA_DIST += $(test_scripts)

pkgconfigdir = $(libdir)/pkgconfig

pkgconfig_DATA = neard.pc

DISTCHECK_CONFIGURE_FLAGS = --enable-tools --enable-ese --disable-systemd

DISTCLEANFILES = $(pkgconfig_DATA)

MAINTAINERCLEANFILES = Makefile.in \
	aclocal.m4 configure config.h.in config.sub config.guess \
	ltmain.sh depcomp compile missing install-sh mkinstalldirs

SED_PROCESS = $(AM_V_GEN)$(MKDIR_P) $(dir $@) && \
		$(SED) -e 's,@pkglibexecdir\@,$(pkglibexecdir),g' \
		< $< > $@

%.service: %.service.in Makefile
	$(SED_PROCESS)

src/plugin.$(OBJEXT): src/builtin.h

src/builtin.h: src/genbuiltin $(builtin_sources)
	$(AM_V_GEN)$(srcdir)/src/genbuiltin $(builtin_modules) > $@

se/plugin.$(OBJEXT): se/builtin.h

se/builtin.h: src/genbuiltin $(builtin_se_sources)
	$(AM_V_GEN)$(srcdir)/src/genbuiltin $(builtin_se_modules) > $@

$(src_neard_OBJECTS) \
$(tools_nfctool_nfctool_OBJECTS) \
$(plugin_objects) \
$(se_seeld_OBJECTS) \
$(unit_test_ndef_parse_OBJECTS) \
$(unit_test_ndef_build_OBJECTS) \
$(unit_test_snep-read_OBJECTS) \
$(tools_snep_send_OBJECTS): $(local_headers)

include/near/version.h: include/version.h
	$(AM_V_at)$(MKDIR_P) include/near
	$(AM_V_GEN)$(LN_S) $(abs_top_builddir)/$< $@

include/near/%.h: $(abs_top_srcdir)/include/%.h
	$(AM_V_at)$(MKDIR_P) include/near
	$(AM_V_GEN)$(LN_S) $< $@

clean-local:
	@$(RM) -rf include/near
