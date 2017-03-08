# Replace PROJECT_NAME with name of the project.
# Replace PATH/TO/SOMEFILE.cpp with the path to some source file.

AC_PREREQ([2.69])
AC_INIT([hasher], [0.1.0], [juckelman@strozfriedberg.co.uk])
 
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/main.cpp])
AC_CONFIG_HEADERS([config.h])
 
AM_INIT_AUTOMAKE([1.12 subdir-objects foreign])
LT_INIT

AC_PROG_CXX
AM_PROG_CC_C_O

AC_LANG([C++])
AX_CXX_COMPILE_STDCXX_14([noext], [mandatory])

AX_APPEND_COMPILE_FLAGS([-W -Wall -Wextra -Wnon-virtual-dtor -pedantic -pipe -O3 -g], [PROJECT_CXXFLAGS])
AX_APPEND_LINK_FLAGS([-g], [PROJECT_LDFLAGS])

#
# Test Dependencies
#

AC_ARG_WITH([scope],
  [AS_HELP_STRING([--with-scope=ARG],
    [use Scope headers from the specified location])],
  [SCOPE_PATH="$withval"],
  [SCOPE_PATH="vendors/scope"])

if test "x$with_scope" != "xno"; then
  # test Scope without adding its path to CPPFLAGS generally
  SCOPE_CPPFLAGS="-isystem `realpath $SCOPE_PATH`"
  CPPFLAGS_saved="$CPPFLAGS"
  CPPFLAGS="$SCOPE_CPPFLAGS"
  export CPPFLAGS

  AC_CHECK_HEADERS([scope/test.h],[scope_ok="yes"])

  CPPFLAGS="$CPPFLAGS_saved"

  if test "x$scope_ok" = "xyes"; then
    AC_DEFINE(HAVE_SCOPE,1,[Define to 1 if Scope test framework is available.])
    AC_SUBST([SCOPE_CPPFLAGS])
  fi
fi

# Tell the user why not if he won't be able to compile the tests
if test "x$scope_ok" != "xyes"; then
  AC_MSG_WARN([])
  AC_MSG_WARN([You will be unable to compile and run the tests because:])
  AC_MSG_WARN([])
  if test "x$scope_ok" != "xyes"; then
    AC_MSG_WARN([  * Scope test framework is unavailable])
  fi
  AC_MSG_WARN([])
fi

AC_SUBST([PROJECT_CPPFLAGS])
AC_SUBST([PROJECT_CXXFLAGS])
AC_SUBST([PROJECT_LDFLAGS])
AC_SUBST([PROJECT_LIBS])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
