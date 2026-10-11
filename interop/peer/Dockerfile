# Copyright 2026 Abhinav Gautam
# SPDX-License-Identifier: Apache-2.0
#
# Reference KNXnet/IP tunnelling server for the interop tests: knxd
# 0.14.54.1 (GPL-2.0, github.com/knxd/knxd) and its tools from Debian
# bookworm. Used only as a test peer; nothing of it is linked into or
# shipped with this module.
#
#   docker build -t sigma-knx-interop:knxd-0.14.54.1 .

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends knxd=0.14.54.1 knxd-tools=0.14.54.1 \
 && rm -rf /var/lib/apt/lists/*
COPY start.sh /start.sh
RUN chmod 0755 /start.sh
ENTRYPOINT ["/start.sh"]
