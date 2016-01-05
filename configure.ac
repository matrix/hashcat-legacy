AC_PREREQ([2.69])
AC_INIT([hashcat], [2.00], [atom@hashcat.net])
AC_CANONICAL_TARGET
AC_CANONICAL_HOST
AC_CANONICAL_SYSTEM
AC_CONFIG_SRCDIR([include/rp.h])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_MAKE_SET

case "$host_cpu" in
	amd64|x86_64)
		cpu_x86_64=true
		AC_DEFINE(CPU_X86_64)
		AH_TEMPLATE(CPU_X86_64, [define if building for x86_64])
		;;
	i*86)
		cpu_x86=true
		AC_DEFINE(CPU_X86)
		AH_TEMPLATE(CPU_X86, [define if building for x86])
		;;
esac

AM_CONDITIONAL(CPU_X86_64, test "x$cpu_x86_64" = xtrue)
AM_CONDITIONAL(CPU_X86, test "x$cpu_x86" = xtrue)

case "$host_os" in
	*linux*)
		host_linux=true
		AC_DEFINE(HOST_IS_LINUX)
		AH_TEMPLATE(HOST_IS_LINUX, [define if building for linux])
		AC_CHECK_LIB(pthread, pthread_create,, [AC_MSG_ERROR([required library pthread missing (libpthread)])])
		;;
	*darwin*)
		host_darwin=true
		AC_DEFINE(HOST_IS_DARWIN)
		AH_TEMPLATE(HOST_IS_DARWIN, [define if building for darwin])
		AC_CHECK_LIB(pthread, pthread_create,, [AC_MSG_ERROR([required library pthread missing (libpthread)])])
		;;
	*mingw32*)
		host_windows=true
		AC_DEFINE(HOST_IS_WINDOWS)
		AH_TEMPLATE(HOST_IS_WINDOWS, [define if building for windows])
		;;
esac

AM_CONDITIONAL(HOST_IS_LINUX, test "x$host_linux" = xtrue)
AM_CONDITIONAL(HOST_IS_DARWIN, test "x$host_darwin" = xtrue)
AM_CONDITIONAL(HOST_IS_WINDOWS, test "x$host_windows" = xtrue)

# Checks for libraries.
AC_CHECK_LIB(m, cos,, [AC_MSG_ERROR([required library math missing (libm)])])
AC_CHECK_LIB(gmp, __gmpz_init,, [AC_MSG_ERROR([required library gmp not found (libgmp)])])

# Checks for XOP AVX AVX2
AC_MSG_CHECKING(whether we can compile AVX code)
AC_COMPILE_IFELSE([AC_LANG_PROGRAM(,[asm ("vmovdqa %ymm0, %ymm1");])],
  with_avx=true
  AC_DEFINE(USE_AVX, 1, [Define to 1 if AVX assembly is available.])
  AC_MSG_RESULT(yes)
  AC_MSG_CHECKING(whether we can compile XOP code)
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM(,[asm ("vprotd \$7, %xmm0, %xmm1");])],
    with_xop=true
    AC_DEFINE(USE_XOP, 1, [Define to 1 if XOP assembly is available.])
    AC_MSG_RESULT(yes)
  ,
    AC_MSG_RESULT(no)
    AC_MSG_WARN([The assembler does not support the XOP instruction set.])
  )
  AC_MSG_CHECKING(whether we can compile AVX2 code)
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM(,[asm ("vpaddd %ymm0, %ymm1, %ymm2");])],
    with_avx2=true
    AC_DEFINE(USE_AVX2, 1, [Define to 1 if AVX2 assembly is available.])
    AC_MSG_RESULT(yes)
  ,
    AC_MSG_RESULT(no)
    AC_MSG_WARN([The assembler does not support the AVX2 instruction set.])
  )
,
  AC_MSG_RESULT(no)
  AC_MSG_WARN([The assembler does not support the AVX instruction set.])
)

AM_CONDITIONAL(USE_AVX, test "x$with_avx" = xtrue)
AM_CONDITIONAL(USE_AVX2, test "x$with_avx2" = xtrue)
AM_CONDITIONAL(USE_XOP, test "x$with_xop" = xtrue)

# Checks for header files.
AC_CHECK_HEADERS([stdint.h stdlib.h string.h sys/ioctl.h sys/time.h termio.h termios.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([gettimeofday memset select strchr strdup strerror strrchr strstr])

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
