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

# diffutils: Rawhide/35 needs "cmp" for configure
dnf -y install \
	autoconf \
	autoconf-archive \
	automake \
	dbus-devel \
	diffutils \
	glib2-devel \
	libnl3-devel \
	libtool \
	make \
	pkg-config \
	$PKGS_CC \
	$PKGS_MORE

echo "Install finished: $0"
