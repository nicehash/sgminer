#!/bin/sh
# bs_dir="$(dirname $(readlink -f $0))"
if [ "$(uname -s)" = 'Linux' ]; then
  bs_dir=$(dirname "$(readlink -f "$0" || echo "$(echo "$0" | sed -e 's,\\,/,g')")")
else
  bs_dir=$(dirname "$(readlink "$0" || echo "$(echo "$0" | sed -e 's,\\,/,g')")")
fi

#Some versions of libtoolize don't like there being no ltmain.sh file already
touch "${bs_dir}"/ltmain.sh
autoreconf -fi "${bs_dir}"
