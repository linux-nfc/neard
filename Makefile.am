
AM_MAKEFLAGS = --no-print-directory

includedir = @includedir@/near

noinst_HEADERS = include/dbus.h include/types.h

local_headers = $(foreach file,$(include_HEADERS) $(nodist_include_HEADERS) \
			$(noinst_HEADERS), include/near/$(notdir $(file)))

gdbus_sources = gdbus/gdbus.h gdbus/mainloop.c gdbus/watch.c \
					gdbus/object.c gdbus/polkit.c

builtin_modules =
builtin_sources =
builtin_cflags =
builtin_libadd =

libexec_PROGRAMS = src/neard

src_neard_SOURCES = $(gdbus_sources) $(gweb_sources) $(builtin_sources) \
			src/main.c src/error.c src/near.h src/log.h src/log.c \
			src/dbus.c src/manager.c src/adapter.c src/netlink.c

src_neard_LDADD = $(builtin_libadd) @GLIB_LIBS@ @DBUS_LIBS@ @NETLINK_LIBS@ -lresolv -ldl

src_neard_LDFLAGS = -Wl,--export-dynamic

nodist_src_neard_SOURCES = src/builtin.h

src/builtin.h: src/genbuiltin $(builtin_sources)
	$(AM_V_GEN)$(srcdir)/src/genbuiltin $(builtin_modules) > $@

AM_CFLAGS = @GLIB_CFLAGS@ @DBUS_CFLAGS@ @NETLINK_CFLAGS@ $(builtin_cflags) \
					-DNEARD_PLUGIN_BUILTIN \
					-DPLUGINDIR=\""$(plugindir)"\"

INCLUDES = -I$(builddir)/include -I$(builddir)/src -I$(srcdir)/gdbus

CLEANFILES = src/builtin.h $(local_headers)

doc_files = doc/manager-api.txt doc/target-api.txt doc/adapter-api.txt

EXTRA_DIST = src/genbuiltin $(doc_files)

test_scripts = test/list-adapters

if TEST
testdir = $(pkglibdir)/test
test_SCRIPTS = $(test_scripts)
endif

EXTRA_DIST += $(test_scripts)

MAINTAINERCLEANFILES = Makefile.in \
	aclocal.m4 configure config.h.in config.sub config.guess \
	ltmain.sh depcomp compile missing install-sh mkinstalldirs

$(src_neard_OBJECTS) $(plugin_objects): $(local_headers)

include/near/%.h: include/%.h
	$(AM_V_at)$(MKDIR_P) include/near
	$(AM_V_GEN)$(LN_S) $(abs_top_srcdir)/$< $@

clean-local:
	@$(RM) -rf include/near
