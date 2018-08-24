#!/bin/bash -ex

. $HOME/vendors/build_config.sh

clean_it

./bootstrap.sh

build_it
install_it

EXES="src/$EXE_DOT_LIBS/hasher$EXE_EXT \
src/$EXE_DOT_LIBS/matcher$EXE_EXT"

STAGE="$EXES python/hasher.py"

case "$Target" in
linux)
  STAGE+=' src/.libs/libhasher.so*'
  ;;

windows)
  case "$Linkage" in
  shared)
    DLL='src/.libs/libhasher.dll'
    STAGE+=" $DLL $($VENDORS/gather.sh $DLL $EXES $MINGW_ROOT/bin $DEPS/bin | grep -v '/libhasher.dll$')"
    ;;
  shared-fat)
    STAGE+=' src/.libs/libhasher.dll'
    ;;
  static)
    check_static $EXES
    STAGE+=' src/.libs/libhasher.a'
    ;;
  esac
  ;;
esac

archive_it
