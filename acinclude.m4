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

AC_DEFUN([NEARD_PROG_CC_ASAN], [
AC_CACHE_CHECK([whether ${CC-cc} accepts -fsanitize=address], neard_cv_prog_cc_asan, [
	echo 'void f(){}' > conftest.c
	if test -z "`${CC-cc} -fsanitize=address -c conftest.c 2>&1`"; then
		neard_cv_prog_cc_asan=yes
	else
		neard_cv_prog_cc_asan=no
	fi
	rm -rf conftest*
])
])

AC_DEFUN([NEARD_PROG_CC_LSAN], [
AC_CACHE_CHECK([whether ${CC-cc} accepts -fsanitize=leak], neard_cv_prog_cc_lsan, [
	echo 'void f(){}' > conftest.c
	if test -z "`${CC-cc} -fsanitize=leak -c conftest.c 2>&1`"; then
		neard_cv_prog_cc_lsan=yes
	else
		neard_cv_prog_cc_lsan=no
	fi
	rm -rf conftest*
])
])

AC_DEFUN([NEARD_PROG_CC_UBSAN], [
AC_CACHE_CHECK([whether ${CC-cc} accepts -fsanitize=undefined], neard_cv_prog_cc_ubsan, [
	echo 'void f(){}' > conftest.c
	if test -z "`${CC-cc} -fsanitize=undefined -c conftest.c 2>&1`"; then
		neard_cv_prog_cc_ubsan=yes
	else
		neard_cv_prog_cc_ubsan=no
	fi
	rm -rf conftest*
])
])
