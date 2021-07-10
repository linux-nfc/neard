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

# gzip: for distcheck
apk add \
	autoconf \
	autoconf-archive \
	automake \
	gcc \
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
