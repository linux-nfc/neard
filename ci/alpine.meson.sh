#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2019-2021 Petr Vorel <petr.vorel@gmail.com>
# Copyright (c) 2021 Canonical Ltd.
# Author: Krzysztof Kozlowski <krzysztof.kozlowski@canonical.com>
#                             <krzk@kernel.org>
# Copyright (c) 2026 Krzysztof Kozlowski <krzk@kernel.org>
#

set -ex

apk update

PKGS_CC="gcc"
case $CC in
	clang*)
		# On Alpine v3.14 clang fails without gcc:
		# cannot find crtbeginS.o: No such file or directory
		PKGS_CC="clang gcc"
	;;
esac

# Packages needed by CI
PKGS_MORE="file"

apk add \
	binutils \
	dbus-dev \
	glib-dev \
	libnl3-dev \
	meson \
	musl-dev \
	ninja \
	pkgconfig \
	$PKGS_CC \
	$PKGS_MORE

echo "Install finished: $0"
