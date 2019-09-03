# getpagesize.m4 serial 7
dnl Copyright (C) 2002, 2004-2005, 2007, 2010-2011, 2018-2019 Free
dnl Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

AC_DEFUN([gl_FUNC_GETPAGESIZE],
[
  AC_REQUIRE([gl_UNISTD_H_DEFAULTS])
  AC_REQUIRE([AC_CANONICAL_HOST])
  AC_CHECK_FUNCS([getpagesize])
  if test $ac_cv_func_getpagesize = no; then
    HAVE_GETPAGESIZE=0
    AC_CHECK_HEADERS([OS.h])
    if test $ac_cv_header_OS_h = yes; then
      HAVE_OS_H=1
    fi
    AC_CHECK_HEADERS([sys/param.h])
    if test $ac_cv_header_sys_param_h = yes; then
      HAVE_SYS_PARAM_H=1
    fi
  fi
  case "$host_os" in
    mingw*)
      REPLACE_GETPAGESIZE=1
      AC_LIBOBJ([getpagesize])
      ;;
  esac
])
