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
# Dependencies
#

# pkg-config doesn't look in /usr/local/lib on some systems
case "$host" in
*-*-mingw*)
  # pkg-config should not look in /usr/local/lib while cross-compiling
  if test "x$enable_shared_fat" = "xyes"; then
    PKG_CONFIG="$PKG_CONFIG --static"
  fi
  ;;
*)
  if test -z "$PKG_CONFIG_PATH"; then
    PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
  else
    PKG_CONFIG_PATH="$PKG_CONFIG_PATH:/usr/local/lib/pkgconfig"
  fi
  export PKG_CONFIG_PATH
  ;;
esac

AX_PKG_CHECK_MODULES([BOTAN], [], [botan-2])
AX_PKG_CHECK_MODULES([LIGHTGREP], [], [lightgrep])

# Botan requires libssp for static and shared fat builds
if test "x$enable_shared" != "xyes" -o "x$enable_shared_fat" = "xyes"; then
  AS_VAR_APPEND(BOTAN_LIBS, "-lssp")
fi

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

#
# Linking
#

# Ensure that we statically link everything which is not a system lib;
# -all-static includes libstdc++ and libgcc, which are excluded by
# -static.
if test "x$enable_shared" != "xyes"; then
  CXXLD="$CXX -all-static"

  case "$host" in
  i686-*-mingw*)
    # FIXME: Really? This looks like it's just asking for trouble...
    AX_APPEND_LINK_FLAGS([-Wl,--allow-multiple-definition], [HASHER_LIB_LDFLAGS])
    ;;
  esac
else
  CXXLD="$CXX"

  case "$host" in
  *-*-mingw*)
    # -no-undefined is a libtool flag; adding it with AX_APPEND_LINK_FLAGS
    # will fail because that tries flags with LD. So don't do that.
    AX_APPEND_FLAG([-no-undefined], [HASHER_LIB_LDFLAGS])
    HASHER_LIB_LDFLAGS="$HASHER_LIB_LDFLAGS -Wl,--output-def -Wl,src/.libs/$PACKAGE.def"
#    LT_LANG([Windows Resource])
    ;;
  esac
fi

AM_CONDITIONAL([BUILD_DLL], [test "x$enable_shared" = "xyes" && echo "$host" | grep -q mingw])

AC_SUBST([CXXLD])

#
# Fat or thin shared library?
#

AC_ARG_ENABLE([shared-fat],
  [AS_HELP_STRING([--enable-shared-fat],
    [statically link libhasher to its dependencies (MinGW only)])])

if test "x$enable_shared_fat" = "xyes"; then
  case "$host" in
  *-*-mingw*)
    if test "x$enable_shared" != "xyes"; then
      AC_MSG_ERROR([--enable-shared-fat requires --enable-shared.])
    fi
    echo "Enabling fat shared lib. Your shared libhasher is so fat, it will contain all of its dependencies."
    ;;
  *)
    AC_MSG_ERROR([--enable-shared-fat requires building with MinGW.])
    ;;
  esac
fi

#
# Ship out the flags to Makefile.am
#

AC_DEFUN([SF_APPEND], [{
  if test -n "[$]$1"; then
    if test -n "$2"; then
      AS_VAR_APPEND($1, " $2")
    fi
  else
    $1=[$]$2
  fi
}])

# collect the flags from everything which might set some
for lib in BOTAN LIGHTGREP; do
  # fold CFLAGS into CXXFLAGS since everything here is C++
  h="${lib}_CXXFLAGS"
  t=$(eval echo \"\$${lib}_CFLAGS\")
  SF_APPEND($h, $t)

  for var in CPPFLAGS CXXFLAGS LDFLAGS LIBS; do
    h="PROJECT_$var"
    t=$(eval echo \"\$${lib}_$var\")
    SF_APPEND($h, $t)
  done
done

AC_SUBST([PROJECT_CPPFLAGS])
AC_SUBST([PROJECT_CXXFLAGS])
AC_SUBST([PROJECT_LDFLAGS])
AC_SUBST([PROJECT_LIBS])
AC_SUBST([HASHER_LIB_LDFLAGS])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

# Force static linking of dependencies for our fat DLL.
if test "x$enable_shared_fat" = "xyes"; then
  # NB: This is likely to be fragile. It works only because the current
  # version of libtool doesn't alter whole_archive_flag_spec and happens
  # to put it in the right place in the linking command for our DLL.
  sed -i '/^whole_archive_flag_spec=/s/"$/ \\${wl}-static"/' libtool

  # We want NO dependencies for a fat DLL. libgcc_s is a stub for
  # libgcc_s_seh-1.dll. libgcc_eh is the corresponding static lib.
  sed -i '/^postdeps=/s/-lgcc_s/-lgcc_eh/g' libtool

  echo 'Adjusted libtool for building fat DLL'
fi
