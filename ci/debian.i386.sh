#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2018-2020 Petr Vorel <pvorel@suse.cz>
# Copyright (c) 2021 Canonical Ltd.
# Author: Krzysztof Kozlowski <krzysztof.kozlowski@canonical.com>
#                             <krzk@kernel.org>
#

set -ex

dpkg --add-architecture i386
apt update

# gcc-multilib are also needed for clang 32-bit builds
PKGS_CC="gcc-multilib"

apt install -y --no-install-recommends \
	linux-libc-dev:i386

apt install -y --no-install-recommends \
	autoconf:i386 \
	autoconf-archive \
	automake:i386 \
	libdbus-1-dev:i386 \
	libglib2.0-dev:i386 \
	libnl-3-dev:i386 \
	libnl-genl-3-dev:i386 \
	libtool:i386 \
	$PKGS_CC

echo "Install finished: $0"
