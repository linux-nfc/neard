project('neard', 'c',
  version : '0.20',
  license : 'GPL-2.0-only',
  meson_version : '>= 1.1',
  default_options : ['warning_level=1'],
)

cc = meson.get_compiler('c')
pkgconfig = import('pkgconfig')

prefix       = get_option('prefix')
libexecdir   = prefix / get_option('libexecdir')
pkglibexecdir = libexecdir / 'nfc'
libdir       = prefix / get_option('libdir')
pkglibdir    = libdir / meson.project_name()
plugindir    = pkglibdir / 'plugins'
sysconfdir   = get_option('sysconfdir')
configdir    = sysconfdir / 'neard'
includedir   = prefix / get_option('includedir')

opt_nfctypes     = get_option('nfctypes')
opt_p2p          = get_option('p2p')
opt_ese          = get_option('ese')
opt_systemd      = get_option('systemd')
opt_tools        = get_option('tools')
opt_test_scripts = get_option('test')

glib_dep = dependency('glib-2.0', version : '>= 2.28')
dbus_dep = dependency('dbus-1', version : '>= 1.2')
dl_dep = cc.find_library('dl')
systemd_dep = dependency('systemd', required : opt_systemd)

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

top_inc = include_directories('.')

subdir('include')
subdir('gdbus')

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

subdir('src')
subdir('doc')
subdir('unit')
if opt_tools
  subdir('tools')
endif
if opt_test_scripts
  subdir('test')
endif
if opt_ese
  subdir('se')
endif
