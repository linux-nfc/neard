tool_c_args = [
  '-DNEAR_PLUGIN_BUILTIN',
  '-DPLUGINDIR="@0@"'.format(plugindir),
  '-DCONFIGDIR="@0@"'.format(configdir),
]

# nciattach: only needs C stdlib at link time; glib/dbus headers are pulled
# in transitively through src/near.h but no glib/dbus symbols are used.
nciattach_deps = []
foreach dep : [glib_dep, dbus_dep] + netlink_dep
  nciattach_deps += dep.partial_dependency(compile_args : true, link_args : false)
endforeach

executable('nciattach',
  'nciattach.c',
  c_args              : tool_c_args,
  include_directories : [top_inc, src_inc],
  dependencies        : [nciattach_deps, config_dep],
  install             : true,
)

# snep-send: internal test tool, not installed
executable('snep-send',
  'snep-send.c',
  '../src/agent.c',
  '../src/bluetooth.c',
  '../src/dbus.c',
  '../src/error.c',
  '../src/log.c',
  '../src/ndef.c',
  gdbus_sources,
  c_args              : ['-DCONFIGDIR="@0@"'.format(configdir)],
  include_directories : [top_inc, gdbus_inc, src_inc],
  dependencies        : [glib_dep, dbus_dep, config_dep],
)

subdir('nfctool')
