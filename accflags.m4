AC_DEFUN([NEARD_COMPILER_FLAGS], [
	# AX_CHECK_COMPILE_FLAG comes from autoconf-archive
	AC_REQUIRE([AC_PROG_CC])
	m4_ifndef([AX_CHECK_COMPILE_FLAG],[
		AC_MSG_ERROR([You need to install the autoconf-archive package.])
	])

	if (test "${CFLAGS}" = ""); then
		CFLAGS="-Wall -O2 -D_FORTIFY_SOURCE=2"
	fi
	if (test "$USE_MAINTAINER_MODE" = "yes"); then
		CFLAGS="$CFLAGS -Werror -Wextra"
		CFLAGS="$CFLAGS -Wno-unused-parameter"
		CFLAGS="$CFLAGS -Wno-missing-field-initializers"
		CFLAGS="$CFLAGS -Wdeclaration-after-statement"
		CFLAGS="$CFLAGS -Wmissing-declarations"
		CFLAGS="$CFLAGS -Wredundant-decls"
		CFLAGS="$CFLAGS -Wcast-align"
		CFLAGS="$CFLAGS -Wformat=2"
		CFLAGS="$CFLAGS -DG_DISABLE_DEPRECATED"

		AX_CHECK_COMPILE_FLAG([-Wdouble-promotion], [CFLAGS="$CFLAGS -Wdouble-promotion"])
		AX_CHECK_COMPILE_FLAG([-Wundef], [CFLAGS="$CFLAGS -Wundef"])
		AX_CHECK_COMPILE_FLAG([-Wbad-function-cast], [CFLAGS="$CFLAGS -Wbad-function-cast"])
		AX_CHECK_COMPILE_FLAG([-Wmissing-prototypes], [CFLAGS="$CFLAGS -Wmissing-prototypes"])
		AX_CHECK_COMPILE_FLAG([-Wjump-misses-init], [CFLAGS="$CFLAGS -Wjump-misses-init"])
		AX_CHECK_COMPILE_FLAG([-Wpointer-arith], [CFLAGS="$CFLAGS -Wpointer-arith"])
		AX_CHECK_COMPILE_FLAG([-Wshadow], [CFLAGS="$CFLAGS -Wshadow"])
		AX_CHECK_COMPILE_FLAG([-Wstrict-overflow=2], [CFLAGS="$CFLAGS -Wstrict-overflow=2"])

		# GCC v5.0
		AX_CHECK_COMPILE_FLAG([-Wformat-signedness], [CFLAGS="$CFLAGS -Wformat-signedness"])
		# GCC v6.0
		AX_CHECK_COMPILE_FLAG([-Wnull-dereference], [CFLAGS="$CFLAGS -Wnull-dereference"])
		AX_CHECK_COMPILE_FLAG([-Wduplicated-cond], [CFLAGS="$CFLAGS -Wduplicated-cond"])
		# GCC v7.0
		AX_CHECK_COMPILE_FLAG([-Wduplicated-branches], [CFLAGS="$CFLAGS -Wduplicated-branches"])
		AX_CHECK_COMPILE_FLAG([-Wvla-larger-than=1], [CFLAGS="$CFLAGS -Wvla-larger-than=1"])
		AX_CHECK_COMPILE_FLAG([-Walloc-zero], [CFLAGS="$CFLAGS -Walloc-zero"])
		# GCC v8.0
		AX_CHECK_COMPILE_FLAG([-Wstringop-truncation], [CFLAGS="$CFLAGS -Wstringop-truncation"])

		# GCC v7.5 from Ubuntu Bionic incorrectly assumes several loops can overflow, so enable
		# -Wunsafe-loop-optimizations only on newer GCC.
		CC_VERSION=`$CC --version | head -n 1 | sed -e 's/.*\ \(@<:@0-9@:>@\+\.@<:@0-9@:>@\+\.@<:@0-9@:>@\+\)\(-@<:@0-9@:>@\+\)\?$/\1/'`
		AX_COMPARE_VERSION([$CC_VERSION],[ge],[8.0.0],
			[AX_CHECK_COMPILE_FLAG([-Wunsafe-loop-optimizations], [CFLAGS="$CFLAGS -Wunsafe-loop-optimizations"])], [])
	fi
	if (test "$USE_MAINTAINER_MODE" = "pedantic"); then
		AX_CHECK_COMPILE_FLAG([-Wcast-qual], [CFLAGS="$CFLAGS -Wcast-qual"])
		# Instead of -Wstrict-overflow=2
		AX_CHECK_COMPILE_FLAG([-Wstrict-overflow=3], [CFLAGS="$CFLAGS -Wstrict-overflow=3"])
	fi
])
