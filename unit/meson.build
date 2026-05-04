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

test_c_args = ['-DCONFIGDIR="@0@"'.format(configdir)]
test_deps   = [glib_dep, dbus_dep, config_dep]

test_ndef_parse = executable('test-ndef-parse',
  'test-ndef-parse.c',
  test_base_sources,
  c_args              : test_c_args,
  include_directories : [top_inc, src_inc, gdbus_inc],
  dependencies        : test_deps,
  build_by_default    : false,
)

test_ndef_build = executable('test-ndef-build',
  'test-ndef-build.c',
  test_base_sources,
  c_args              : test_c_args,
  include_directories : [top_inc, src_inc, gdbus_inc],
  dependencies        : test_deps,
  build_by_default    : false,
)

test_snep_read = executable('test-snep-read',
  'test-snep-read.c',
  'test-utils.c',
  '../src/snep.c',
  test_base_sources,
  c_args              : test_c_args,
  include_directories : [top_inc, src_inc, gdbus_inc],
  dependencies        : test_deps,
  build_by_default    : false,
)

test('test-ndef-parse', test_ndef_parse)
test('test-ndef-build', test_ndef_build)
test('test-snep-read',  test_snep_read)
