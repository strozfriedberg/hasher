#!/bin/bash -ex

. .world/build_config.sh

install_it

mkdir -p $INSTALL/lib/python
cp -av python $INSTALL/lib/python/hasher
cp utils/{hsdump.py,hsinfo.py,mkhashset.py,nsrldump.py} $INSTALL/lib/python
