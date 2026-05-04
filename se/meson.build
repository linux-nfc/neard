# seeld - Secure Element daemon
# Only processed when -Dese=true is passed to meson setup.

# ---------------------------------------------------------------------------
# SE builtin plugin modules
# ---------------------------------------------------------------------------

# Generate builtin.h for seeld.
# custom_target output goes to <builddir>/se/builtin.h, which is found via
# include_directories('.') below ('-I<builddir>/se').
seeld_builtin_h = configure_file(
  output  : 'builtin.h',
  command : [genbuiltin, 'nfc'],
  capture : true,
)

# se_inc must come before top_inc so <builtin.h> resolves to
# <builddir>/se/builtin.h rather than the neard <builddir>/builtin.h.
se_inc = include_directories('.')

# ---------------------------------------------------------------------------
# seeld daemon
# ---------------------------------------------------------------------------

seeld_c_args = [
  '-DNEAR_PLUGIN_BUILTIN',
  '-DPLUGINDIR="' + (prefix / get_option('libdir') / meson.project_name() / 'plugins-se') + '"',
  '-DCONFIGDIR="' + configdir + '"',
]

executable('seeld',
  sources : [
    gdbus_sources,
    files('plugins/nfc.c'),
    seeld_builtin_h,
    files(
      '../src/log.c',
      '../src/dbus.c',
      '../src/error.c',
      '../src/plugin.c',
      'main.c',
      'manager.c',
      'se.c',
      'driver.c',
      'apdu.c',
      'channel.c',
      'ace.c',
    ),
  ],
  c_args              : seeld_c_args,
  include_directories : [se_inc, top_inc],
  dependencies        : [glib_dep, dbus_dep, netlink_dep, dl_dep, config_dep],
  link_args           : ['-Wl,--export-dynamic'],
  install             : true,
  install_dir         : pkglibexecdir,
)

# ---------------------------------------------------------------------------
# D-Bus configuration
# ---------------------------------------------------------------------------

install_data(
  'org.neard.se.conf',
  install_dir : get_option('sysconfdir') / 'dbus-1' / 'system.d',
)

# ---------------------------------------------------------------------------
# pkg-config file (for seeld plugin developers)
# ---------------------------------------------------------------------------

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
