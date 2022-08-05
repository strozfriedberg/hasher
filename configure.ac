# Replace PROJECT_NAME with name of the project.
# Replace PATH/TO/SOMEFILE.cpp with the path to some source file.

AC_PREREQ([2.69])
AC_INIT([hasher], [0.3.0], [juckelman@strozfriedberg.co.uk])

AC_CONFIG_AUX_DIR([config])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/hasher.cpp])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([1.12 subdir-objects foreign])
LT_INIT

AM_PROG_AS
AC_PROG_CXX
AM_PROG_CC_C_O

AC_LANG([C++])
AX_CXX_COMPILE_STDCXX_17([noext], [mandatory])

AX_APPEND_COMPILE_FLAGS([-W -Wall -Wextra -Wnon-virtual-dtor -pedantic -pipe -O3 -g], [PROJECT_CXXFLAGS])
AX_APPEND_LINK_FLAGS([-g], [PROJECT_LDFLAGS])

#
# Define platform macroses
#
# AC_CANONICAL_HOST is needed to access the 'host_os' variable
AC_CANONICAL_HOST

# Detect the target system
case "${host_os}" in
    linux*)
        AC_DEFINE([_LINUX], [1], [Linux platform])
        ;;
    cygwin*|mingw*)
        AC_DEFINE([_WIN32], [1], [Windows platform])
        ;;
    darwin*)
        AC_DEFINE([_MACOSX], [1], [Macosx platform])
        ;;
    *)
        AC_MSG_ERROR(["OS $host_os is not supported"])
        ;;
esac

#
# Dependencies
#

PKG_PROG_PKG_CONFIG
AS_IF([test "x$enable_shared" != "xyes"], [PKG_CONFIG="$PKG_CONFIG --static"])

AX_PKG_CHECK_MODULES([CRYPTO], [], [libcrypto])

AX_CHECK_LIBRARY([FUZZY], [fuzzy.h], [fuzzy],
                 [FUZZY_LIBS=-lfuzzy],
                 [AC_MSG_ERROR([Failed to find libfuzzy])])
AC_SUBST([FUZZY_LIBS])

if test "x$with_boost" = "xno"; then
  AC_MSG_ERROR([--without-boost specified, but Boost is mandatory.])
else
  case "$host" in
  *-*-mingw*)
    # AX_BOOST_BASE doesn't find Boost for mingw, we help it out
    if test "$with_boost" = ""; then
      with_boost="/usr/${host}/sys-root/mingw"
      AC_MSG_WARN([--with-boost not set. We are guessing ${with_boost}.])
    fi
    ;;
  esac

  AX_BOOST_BASE([1.49.0],
    [],
    [AC_MSG_ERROR([Failed to find usable Boost headers.])])
fi

#
# Test Dependencies
#

AX_PKG_CHECK_MODULES([CATCH2], [], [catch2-with-main])

#
# Linking
#

# Ensure that we statically link everything which is not a system lib;
# -all-static includes libstdc++ and libgcc, which are excluded by
# -static.
if test "x$enable_shared" != "xyes"; then
  CXXLD="$CXX -all-static"
  CCLD="$CXX -all-static"

  case "$host" in
  i686-*-mingw*)
    # FIXME: Really? This looks like it's just asking for trouble...
    AX_APPEND_LINK_FLAGS([-Wl,--allow-multiple-definition], [HASHER_LIB_LDFLAGS])
    ;;
  esac
else
  CXXLD="$CXX"
  CCLD="$CC"

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
AC_SUBST([CCLD])

AM_CONDITIONAL([HOST_32_BIT], [test "x$host_cpu" = "xi686"])
AM_CONDITIONAL([HOST_WINDOWS], [echo "$host_os" | grep -q mingw])

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

    TEST_LIBS=
    ;;
  *)
    AC_MSG_ERROR([--enable-shared-fat requires building with MinGW.])
    ;;
  esac
else
  TEST_LIBS="$PROJECT_LIBS"
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
for lib in BOOST CRYPTO FUZZY; do
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
AC_SUBST([TEST_LIBS])

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
