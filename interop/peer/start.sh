#!/bin/sh
# Copyright 2026 Abhinav Gautam
# SPDX-License-Identifier: Apache-2.0
#
# Entry point of the knxd interop image. Without arguments it runs knxd as
# a KNXnet/IP server (search, description, tunnelling) on UDP 3671 with
# its own individual address 1.1.1, tunnel addresses from 1.1.10, and a
# local socket for knxtool; anything else is run as a command.
set -e
if [ "$#" -gt 0 ]; then
	exec "$@"
fi
exec knxd -e 1.1.1 -E 1.1.10:8 -u /tmp/eib -D -T -S -b dummy:
