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
	autoconf \
	autoconf-archive \
	automake \
	libdbus-1-dev \
	libglib2.0-dev \
	libnl-3-dev \
	libnl-genl-3-dev \
	libtool \
	make \
	$PKGS_CC

echo "Install finished: $0"
