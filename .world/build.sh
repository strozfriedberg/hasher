#!/bin/bash -ex

. .world/build_config.sh

make_it

if [ "$Target" = 'windows' ]; then
  MAKE_FLAGS+=' LOG_COMPILER=wine'
fi

make_check_it
