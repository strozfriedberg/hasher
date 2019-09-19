#!/bin/bash -ex

. jenkins-setup/build_config.sh

./bootstrap.sh

CONFIGURE="$CONFIGURE --with-boost=$DEPS"
build_it
install_it

mkdir -p $INSTALL/lib/python
cp python/hasher.py $INSTALL/lib/python
