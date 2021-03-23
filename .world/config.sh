#!/bin/bash -ex

. .world/build_config.sh

# Avoid macOS's inability to use DYLD_LIBRARY_PATH with SIP, or otherwise
# resolve local boosts.
if [ "$Target" = 'macos' ]; then
  CONFIGURE="$CONFIGURE --with-boost=/usr/local"
fi

configure_it
