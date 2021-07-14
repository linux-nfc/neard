#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2021 Canonical Ltd.
# Author: Krzysztof Kozlowski <krzysztof.kozlowski@canonical.com>
#                             <krzk@kernel.org>
#

set -ex

apt install -y --no-install-recommends \
	liblsan0 \
	libubsan1

apt install -y --no-install-recommends libasan6 || \
	apt install -y --no-install-recommends libasan5

echo "Install finished: $0"
