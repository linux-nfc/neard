#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2018-2020 Petr Vorel <pvorel@suse.cz>
# Copyright (c) 2021 Canonical Ltd.
# Author: Krzysztof Kozlowski <krzysztof.kozlowski@canonical.com>
#                             <krzk@kernel.org>
#

set -ex

if [ -z "$ARCH" ]; then
	echo "missing \$ARCH!" >&2
	exit 1
fi

dpkg --add-architecture $ARCH
apt update

apt install -y --no-install-recommends \
	autoconf:${ARCH} \
	autoconf-archive \
	automake:${ARCH} \
	libdbus-1-dev:${ARCH} \
	libglib2.0-dev:${ARCH} \
	libnl-3-dev:${ARCH} \
	libnl-genl-3-dev:${ARCH} \
	libtool:${ARCH} \
	gcc-`dpkg-architecture -a ${ARCH} -q DEB_TARGET_GNU_TYPE`

echo "Install finished: $0"
