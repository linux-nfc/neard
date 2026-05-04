# seeld - Secure Element daemon

seeld_builtin_h = configure_file(
  output  : 'builtin.h',
  command : [genbuiltin, 'nfc'],
  capture : true,
)

se_inc = include_directories('.')

seeld_c_args = [
  '-DNEAR_PLUGIN_BUILTIN',
  '-DPLUGINDIR="' + (prefix / get_option('libdir') / meson.project_name() / 'plugins-se') + '"',
  '-DCONFIGDIR="' + configdir + '"',
]

executable('seeld',
  'ace.c',
  'apdu.c',
  'channel.c',
  'driver.c',
  'main.c',
  'manager.c',
  'plugins/nfc.c',
  'se.c',
  '../src/dbus.c',
  '../src/error.c',
  '../src/log.c',
  '../src/plugin.c',
  gdbus_sources,
  seeld_builtin_h,
  c_args              : seeld_c_args,
  include_directories : [se_inc, top_inc, src_inc, gdbus_inc],
  dependencies        : [glib_dep, dbus_dep, netlink_dep, dl_dep, config_dep],
  link_args           : ['-Wl,--export-dynamic'],
  install             : true,
  install_dir         : pkglibexecdir,
)

install_data(
  'org.neard.se.conf',
  install_dir : get_option('sysconfdir') / 'dbus-1' / 'system.d',
)

pkgconfig.generate(
  name         : 'seeld',
  description  : 'Secure Element daemon',
  version      : meson.project_version(),
  requires     : [glib_dep, dbus_dep],
  libraries    : ['-module', '-avoid-version', '-export-symbols-regex', 'seeld_plugin_desc'],
  variables    : {
    'plugindir' : '${libdir}/seeld/plugins',
  },
)
