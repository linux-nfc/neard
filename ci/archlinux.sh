#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2021 Canonical Ltd.
# Author: Krzysztof Kozlowski <krzysztof.kozlowski@canonical.com>
#                             <krzk@kernel.org>
#

set -ex

PKGS_CC="gcc"
case $CC in
	clang*)
		PKGS_CC="clang"
	;;
esac

pacman -Sy --noconfirm \
	autoconf \
	autoconf-archive \
	automake \
	dbus \
	glib2 \
	libnl \
	libtool \
	make \
	pkg-config \
	$PKGS_CC

echo "Install finished: $0"
