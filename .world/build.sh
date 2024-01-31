#!/bin/bash -ex

. .world/build_config.sh

make_it

if [ "$Target" = 'windows' ]; then
  MAKE_FLAGS+=' LOG_COMPILER=.world/wine_wrapper.sh'
fi

make_check_it

if [[ "$Target" == 'linux' && "$Linkage" == 'shared' ]]; then
  # Build a Python wheel
  VENV=.venv
  if [[ "$Target" == 'windows' ]]; then
    PYTHON=python
    VENVBIN=Scripts
  else
    PYTHON=python3
    VENVBIN=bin
  fi

  pushd python
  $PYTHON -m venv $VENV
  . "$VENV/$VENVBIN/activate"
  pip install build
  $PYTHON -m build -w
  deactivate
  popd
fi
