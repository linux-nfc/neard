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

# Packages needed by CI
PKGS_MORE="file"

dnf -y install \
	dbus-devel \
	glib2-devel \
	libnl3-devel \
	meson \
	ninja-build \
	pkg-config \
	$PKGS_CC \
	$PKGS_MORE

echo "Install finished: $0"
