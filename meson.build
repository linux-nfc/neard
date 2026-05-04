project('neard', 'c',
  version : '0.20',
  license : 'GPL-2.0-only',
  meson_version : '>= 1.1',
  default_options : ['warning_level=1'],
)

cc = meson.get_compiler('c')
pkgconfig = import('pkgconfig')

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------

glib_dep = dependency('glib-2.0', version : '>= 2.28')
dbus_dep = dependency('dbus-1', version : '>= 1.2')
dl_dep = cc.find_library('dl')

# Netlink: prefer libnl-3.0, fall back to libnl-2.0, then libnl-1
libnl3_dep = dependency('libnl-3.0', required : false)
libnl_genl3_dep = dependency('libnl-genl-3.0', required : false)
if libnl3_dep.found() and libnl_genl3_dep.found()
  netlink_dep = [libnl3_dep, libnl_genl3_dep]
  netlink_deps_str = 'libnl-3.0 libnl-genl-3.0'
  need_libnl_compat = false
else
  libnl2_dep = dependency('libnl-2.0', required : false)
  if libnl2_dep.found()
    netlink_dep = [libnl2_dep]
    netlink_deps_str = 'libnl-2.0'
    need_libnl_compat = false
  else
    libnl1_dep = dependency('libnl-1', required : true)
    netlink_dep = [libnl1_dep]
    netlink_deps_str = 'libnl-1'
    need_libnl_compat = true
  endif
endif

# ---------------------------------------------------------------------------
# Build options
# ---------------------------------------------------------------------------

opt_nfctypes     = get_option('nfctypes')
opt_p2p          = get_option('p2p')
opt_ese          = get_option('ese')
opt_systemd      = get_option('systemd')
opt_tools        = get_option('tools')
opt_test_scripts = get_option('test')

# ---------------------------------------------------------------------------
# Install directories
# ---------------------------------------------------------------------------

prefix       = get_option('prefix')
libexecdir   = prefix / get_option('libexecdir')
pkglibexecdir = libexecdir / 'nfc'
libdir       = prefix / get_option('libdir')
pkglibdir    = libdir / meson.project_name()
plugindir    = pkglibdir / 'plugins'
sysconfdir   = get_option('sysconfdir')
configdir    = sysconfdir / 'neard'
includedir   = prefix / get_option('includedir')

# ---------------------------------------------------------------------------
# Generated headers
# ---------------------------------------------------------------------------

conf = configuration_data()
conf.set_quoted('VERSION', meson.project_version())
conf.set_quoted('PACKAGE', meson.project_name())
conf.set_quoted('PACKAGE_VERSION', meson.project_version())
if need_libnl_compat
  conf.set('NEED_LIBNL_COMPAT', 1)
endif
config_h = configure_file(output : 'config.h', configuration : conf)
config_dep = declare_dependency(
  include_directories: include_directories(),
  sources: config_h,
  compile_args: ['-DHAVE_CONFIG_H'],
)

subdir('include')

# Creates <builddir>/src/near/version.h (and all other near/ headers).
# include_directories('src') adds both <srcdir>/src and <builddir>/src to the
# search path, so "#include <near/foo.h>" resolves to <builddir>/src/near/foo.h.
subdir('src/near')

# ---------------------------------------------------------------------------
# Include directories
# ---------------------------------------------------------------------------

# '.' adds both <srcdir> and <builddir> (provides config.h)
# 'src' adds both <srcdir>/src and <builddir>/src (provides near/*.h via src/near/)
# 'gdbus' is needed for gdbus.h
top_inc = include_directories('.', 'src', 'gdbus')

# ---------------------------------------------------------------------------
# gdbus helper sources (compiled directly into each binary that needs them)
# ---------------------------------------------------------------------------

gdbus_sources = files(
  'gdbus/mainloop.c',
  'gdbus/watch.c',
  'gdbus/object.c',
  'gdbus/client.c',
  'gdbus/polkit.c',
)

# ---------------------------------------------------------------------------
# Builtin plugin modules (compiled into neard)
# ---------------------------------------------------------------------------

genbuiltin = find_program('src/genbuiltin')

builtin_modules = opt_nfctypes
builtin_sources = []

sources_per_type = {
  'nfctype1': files('plugins/nfctype1.c'),
  'nfctype2': files('plugins/nfctype2.c', 'plugins/mifare.c'),
  'nfctype3': files('plugins/nfctype3.c'),
  'nfctype4': files('plugins/nfctype4.c'),
  'nfctype5': files('plugins/nfctype5.c'),
}

foreach nfctype : opt_nfctypes
  builtin_sources += sources_per_type[nfctype]
endforeach

if opt_p2p
  builtin_modules += ['p2p']
  builtin_sources += files(
    'plugins/p2p.c',
    'plugins/npp.c',
    'plugins/snep.c',
    'plugins/snep-validation.c',
    'plugins/llcp-validation.c',
    'plugins/handover.c',
    'plugins/phdc.c',
  )
endif

builtin_h = configure_file(
  output  : 'builtin.h',
  command : [genbuiltin] + builtin_modules,
  capture : true,
)

# ---------------------------------------------------------------------------
# neard daemon
# ---------------------------------------------------------------------------

neard_c_args = [
  '-DNEAR_PLUGIN_BUILTIN',
  '-DPLUGINDIR="' + plugindir + '"',
  '-DCONFIGDIR="' + configdir + '"',
]

neard_deps = [
  glib_dep,
  dbus_dep,
  netlink_dep,
  dl_dep,
  config_dep,
]

neard = executable('neard',
  sources : [
    config_h,
    gdbus_sources,
    builtin_sources,
    builtin_h,
    files(
      'src/main.c',
      'src/error.c',
      'src/log.c',
      'src/dbus.c',
      'src/manager.c',
      'src/adapter.c',
      'src/device.c',
      'src/tag.c',
      'src/plugin.c',
      'src/netlink.c',
      'src/ndef.c',
      'src/tlv.c',
      'src/bluetooth.c',
      'src/agent.c',
      'src/snep.c',
    ),
  ],
  c_args              : neard_c_args,
  include_directories : top_inc,
  dependencies        : neard_deps,
  install             : true,
  install_dir         : pkglibexecdir,
)

# ---------------------------------------------------------------------------
# Systemd service file
# ---------------------------------------------------------------------------

systemd_dep = dependency('systemd', required : opt_systemd)
if systemd_dep.found()
  systemd_unitdir = systemd_dep.get_variable('systemdsystemunitdir')
  service_conf = configuration_data()
  service_conf.set('pkglibexecdir', pkglibexecdir)
  service_file = configure_file(
    input         : 'src/neard.service.in',
    output        : 'neard.service',
    configuration : service_conf,
  )
  install_data(service_file, install_dir : systemd_unitdir)
endif

# ---------------------------------------------------------------------------
# Configuration and D-Bus files
# ---------------------------------------------------------------------------

install_data(
  'src/org.neard.conf',
  install_dir : sysconfdir / 'dbus-1' / 'system.d',
)

install_data(
  'src/main.conf',
  install_dir : configdir,
)

# ---------------------------------------------------------------------------
# Public headers
# ---------------------------------------------------------------------------

install_headers(
  'include/types.h',
  'include/log.h',
  'include/plugin.h',
  'include/tag.h',
  'include/adapter.h',
  'include/ndef.h',
  'include/tlv.h',
  'include/setting.h',
  'include/device.h',
  'include/nfc_copy.h',
  'include/snep.h',
  subdir : 'near',
)

# ---------------------------------------------------------------------------
# pkg-config file (for plugin developers)
# ---------------------------------------------------------------------------

pkgconfig.generate(
  name         : 'neard',
  description  : 'NFC daemon',
  version      : meson.project_version(),
  requires     : [glib_dep, dbus_dep, netlink_dep],
  libraries    : ['-module', '-avoid-version', '-export-symbols-regex', 'neard_plugin_desc'],
  variables    : {
    'pkglibdir' : '${libdir}/' + meson.project_name(),
    'plugindir' : '${libdir}/' + meson.project_name() + '/plugins',
  },
)

# ---------------------------------------------------------------------------
# Man pages
# ---------------------------------------------------------------------------

install_man('doc/neard.8', 'doc/neard.conf.5')

# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------

subdir('unit')

# ---------------------------------------------------------------------------
# Tools (optional)
# ---------------------------------------------------------------------------

if opt_tools
  subdir('tools')
endif

# ---------------------------------------------------------------------------
# Test scripts (optional install)
# ---------------------------------------------------------------------------

if opt_test_scripts
  subdir('test')
endif

# ---------------------------------------------------------------------------
# Embedded Secure Element daemon (seeld)
# ---------------------------------------------------------------------------

if opt_ese
  subdir('se')
endif
