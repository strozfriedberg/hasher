#!/bin/bash -e

if [ -e src/lib/.libs/libhasher.so ]; then
  LIBS=$(realpath src/lib/.libs)
  pushd python
  LD_LIBRARY_PATH=$LIBS:$LD_LIBRARY_PATH python3 -m unittest -v
  popd
fi
