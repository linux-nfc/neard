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

case "$ARCH" in
	armel) PKGS_CC="gcc-arm-linux-gnueabi";;
	arm64) PKGS_CC="gcc-aarch64-linux-gnu";;
	ppc64el) PKGS_CC="gcc-powerpc64le-linux-gnu";;
	# TODO: libraries for riscv?
	#riscv64) PKGS_CC="gcc-riscv64-linux-gnu";;
	s390x) PKGS_CC="gcc-${ARCH}-linux-gnu";;
	*) echo "unsupported arch: '$ARCH'!" >&2; exit 1;;
esac

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
	$PKGS_CC

echo "Install finished: $0"
