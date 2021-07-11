AC_DEFUN([NEARD_PROG_CC_PIE], [
	AC_CACHE_CHECK([whether ${CC-cc} accepts -fPIE], neard_cv_prog_cc_pie, [
		echo 'void f(){}' > conftest.c
		if test -z "`${CC-cc} -fPIE -pie -c conftest.c 2>&1`"; then
			neard_cv_prog_cc_pie=yes
		else
			neard_cv_prog_cc_pie=no
		fi
		rm -rf conftest*
	])
])
