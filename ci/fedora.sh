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

yum -y install \
	autoconf \
	autoconf-archive \
	automake \
	dbus-devel \
	glib2-devel \
	libnl3-devel \
	libtool \
	make \
	$PKGS_CC

# Packages needed by CI
yum -y install \
	file

echo "Install finished: $0"
