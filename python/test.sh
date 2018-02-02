#!/bin/bash -e

if [ -e src/.libs/libhasher.so ]; then
  LD_LIBRARY_PATH=src/.libs:$LD_LIBRARY_PATH python/test.py -v
fi
