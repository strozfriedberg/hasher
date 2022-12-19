#!/bin/bash -e

if [ -e src/lib/.libs/libhasher.so ]; then
  LD_LIBRARY_PATH=src/lib/.libs:$LD_LIBRARY_PATH python/test.py -v
fi
