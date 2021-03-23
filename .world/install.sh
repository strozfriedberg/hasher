#!/bin/bash -ex

. .world/build_config.sh

install_it

mkdir -p $INSTALL/lib/python
cp python/hasher.py utils/{hsdump.py,hsinfo.py,mkhashset.py,nsrldump.py} $INSTALL/lib/python
