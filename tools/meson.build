tool_c_args = [
  '-DNEAR_PLUGIN_BUILTIN',
  '-DPLUGINDIR="' + plugindir + '"',
  '-DCONFIGDIR="' + configdir + '"',
]

executable('nfctool',
  sources : files(
    'nfctool/main.c',
    'nfctool/adapter.c',
    'nfctool/netlink.c',
    'nfctool/sniffer.c',
    'nfctool/llcp-decode.c',
    'nfctool/snep-decode.c',
    'nfctool/ndef-decode.c',
    'nfctool/display.c',
  ),
  c_args              : tool_c_args,
  include_directories : top_inc,
  dependencies        : [glib_dep, netlink_dep, config_dep],
  install             : true,
)

# nciattach: only needs C stdlib at link time; glib/dbus headers are pulled
# in transitively through src/near.h but no glib/dbus symbols are used.
nciattach_deps = []
foreach dep : [glib_dep, dbus_dep] + netlink_dep
  nciattach_deps += dep.partial_dependency(compile_args : true, link_args : false)
endforeach

executable('nciattach',
  sources             : files('nciattach.c'),
  c_args              : tool_c_args,
  include_directories : top_inc,
  dependencies        : [nciattach_deps, config_dep],
  install             : true,
)

# snep-send: internal test tool, not installed
executable('snep-send',
  sources : [
    gdbus_sources,
    files(
      '../src/log.c',
      '../src/dbus.c',
      '../src/bluetooth.c',
      '../src/ndef.c',
      '../src/error.c',
      '../src/agent.c',
      'snep-send.c',
    ),
  ],
  c_args              : ['-DCONFIGDIR="' + configdir + '"'],
  include_directories : top_inc,
  dependencies        : [glib_dep, dbus_dep, config_dep],
)

install_man('../doc/nfctool.1')
