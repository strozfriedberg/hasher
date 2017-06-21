#!/bin/bash -e

if [ -x src/lib/.libs/libhasher.so ]; then
  LD_LIBRARY_PATH=src/lib/.libs python/test.py -v
fi
