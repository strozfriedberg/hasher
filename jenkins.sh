#!/bin/bash -ex

. jenkins-setup/build_config.sh

unpack_deps

./bootstrap.sh

build_it
install_it

mkdir -p $INSTALL/lib/python
cp python/hasher.py $INSTALL/lib/python

gather_deps
archive_it_ex
