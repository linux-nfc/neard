#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2019-2021 Petr Vorel <petr.vorel@gmail.com>
# Copyright (c) 2021 Canonical Ltd.
# Author: Krzysztof Kozlowski <krzysztof.kozlowski@canonical.com>
#                             <krzk@kernel.org>
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

# gzip: for distcheck
apk add \
	autoconf \
	autoconf-archive \
	automake \
	binutils \
	gzip \
	dbus-dev \
	glib-dev \
	libnl3-dev \
	libtool \
	make \
	musl-dev \
	$PKGS_CC

# Packages needed by CI
apk add \
	file

echo "Install finished: $0"
