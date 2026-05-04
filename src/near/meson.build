# Generate near/ headers in the build directory so that
# "#include <near/foo.h>" resolves at compile time.
# include_directories('src') in the root meson.build adds both
# <srcdir>/src and <builddir>/src to the compiler search path,
# so files generated here (<builddir>/src/near/*.h) are found as
# <near/foo.h>.

foreach file : include_files
  configure_file(
    input  : file,
    output : '@PLAINNAME@',
    copy   : true,
  )
endforeach

version_conf = configuration_data()
version_conf.set('VERSION', meson.project_version())

version_h = configure_file(
  input         : version_h_in,
  output        : '@BASENAME@',
  configuration : version_conf,
  install       : true,
  install_dir   : get_option('includedir') / 'near',
)
