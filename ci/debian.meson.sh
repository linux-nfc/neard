#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2021 Canonical Ltd.
# Author: Krzysztof Kozlowski <krzysztof.kozlowski@canonical.com>
#                             <krzk@kernel.org>
#

set -ex

apt update

# Some distros (e.g. Ubuntu Hirsute) might pull tzdata which asks questions
export DEBIAN_FRONTEND=noninteractive DEBCONF_NONINTERACTIVE_SEEN=true

# Choose some random place in Europe
echo "tzdata tzdata/Areas select Europe
tzdata tzdata/Zones/Europe select Berlin
" > /tmp/tzdata-preseed.txt
debconf-set-selections /tmp/tzdata-preseed.txt

PKGS_CC="build-essential"
case $CC in
	clang*)
		PKGS_CC="clang"
	;;
esac

apt install -y --no-install-recommends \
	file \
	libdbus-1-dev \
	libglib2.0-dev \
	libnl-3-dev \
	libnl-genl-3-dev \
	meson \
	ninja-build \
	pkg-config \
	python3-pip \
	$PKGS_CC

# Meson >= 1.1 is required. If the packaged version is older, install via pip.
MIN_MESON="1.1.0"
MESON_VER=$(meson --version 2>/dev/null || echo "0.0.0")
if dpkg --compare-versions "$MESON_VER" lt "$MIN_MESON"; then
	pip3 install "meson>=$MIN_MESON" 2>/dev/null || \
		pip3 install --break-system-packages "meson>=$MIN_MESON"
fi

echo "Install finished: $0"
