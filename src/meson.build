subdir('near')

src_inc = include_directories('.')

genbuiltin = find_program('genbuiltin')
builtin_h = configure_file(
  output  : 'builtin.h',
  command : [genbuiltin] + builtin_modules,
  capture : true,
)

neard_c_args = [
  '-DNEAR_PLUGIN_BUILTIN',
  '-DPLUGINDIR="@0@"'.format(plugindir),
  '-DCONFIGDIR="@0@"'.format(configdir),
]

neard_deps = [
  glib_dep,
  dbus_dep,
  netlink_dep,
  dl_dep,
  config_dep,
]

neard = executable('neard',
  'adapter.c',
  'agent.c',
  'bluetooth.c',
  'dbus.c',
  'device.c',
  'error.c',
  'log.c',
  'main.c',
  'manager.c',
  'ndef.c',
  'netlink.c',
  'plugin.c',
  'snep.c',
  'tag.c',
  'tlv.c',
  builtin_h,
  builtin_sources,
  config_h,
  gdbus_sources,
  c_args              : neard_c_args,
  include_directories : [top_inc, gdbus_inc],
  dependencies        : neard_deps,
  install             : true,
  install_dir         : pkglibexecdir,
)

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

if systemd_dep.found()
  systemd_unitdir = systemd_dep.get_variable('systemdsystemunitdir')
  service_conf = configuration_data()
  service_conf.set('pkglibexecdir', pkglibexecdir)
  service_file = configure_file(
    input         : 'neard.service.in',
    output        : 'neard.service',
    configuration : service_conf,
  )
  install_data(service_file, install_dir : systemd_unitdir)
endif

install_data(
  'org.neard.conf',
  install_dir : sysconfdir / 'dbus-1' / 'system.d',
)

install_data(
  'main.conf',
  install_dir : configdir,
)
