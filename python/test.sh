#!/bin/bash -e

if [ -e src/.libs/libhasher.so ]; then
  LD_LIBRARY_PATH=src/.libs:/usr/local/lib python/test.py -v
fi
