test_base_sources = [
  gdbus_sources,
  files(
    '../src/log.c',
    '../src/dbus.c',
    '../src/error.c',
    '../src/agent.c',
    '../src/bluetooth.c',
    '../src/ndef.c',
  ),
]

test_c_args = ['-DCONFIGDIR="' + configdir + '"']
test_deps   = [glib_dep, dbus_dep, config_dep]

test_ndef_parse = executable('test-ndef-parse',
  sources             : test_base_sources + [files('test-ndef-parse.c')],
  c_args              : test_c_args,
  include_directories : top_inc,
  dependencies        : test_deps,
  build_by_default    : false,
)

test_ndef_build = executable('test-ndef-build',
  sources             : test_base_sources + [files('test-ndef-build.c')],
  c_args              : test_c_args,
  include_directories : top_inc,
  dependencies        : test_deps,
  build_by_default    : false,
)

test_snep_read = executable('test-snep-read',
  sources : test_base_sources + files(
    '../src/snep.c',
    'test-snep-read.c',
    'test-utils.c',
  ),
  c_args              : test_c_args,
  include_directories : top_inc,
  dependencies        : test_deps,
  build_by_default    : false,
)

test('test-ndef-parse', test_ndef_parse)
test('test-ndef-build', test_ndef_build)
test('test-snep-read',  test_snep_read)
