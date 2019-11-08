#!/bin/bash -ex

. build_setup/build_config.sh

./bootstrap.sh

# Avoid macOS's inability to use DYLD_LIBRARY_PATH with SIP, or otherwise
# resolve local boosts.
if [ "$Target" = 'macos' ]; then
  BOOST_DEPS=/usr/local
else
  BOOST_DEPS=$DEPS
fi

CONFIGURE="$CONFIGURE --with-boost=$BOOST_DEPS"
build_it
install_it

mkdir -p $INSTALL/lib/python
cp python/hasher.py $INSTALL/lib/python

