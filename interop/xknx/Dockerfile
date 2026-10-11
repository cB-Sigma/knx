# Copyright 2026 Abhinav Gautam
# SPDX-License-Identifier: Apache-2.0
#
# Independent readers of ETS files for the interop tests: xknx 3.20.0
# (MIT, github.com/XKNX/xknx) for keyrings and xknxproject 3.10.0
# (GPL-2.0-only, github.com/XKNX/xknxproject) for projects, used only as
# test peers. The sample keyrings and projects of their test suites, which
# ETS wrote, are copied into /samples; nothing of them is kept in this
# repository.
#
#   docker build -t sigma-knx-xknx:3.20.0 .

FROM python:3.12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir xknx==3.20.0 xknxproject==3.10.0 \
 && git clone --depth 1 --branch 3.20.0 https://github.com/XKNX/xknx /tmp/xknx \
 && git clone --depth 1 --branch 3.10.0 https://github.com/XKNX/xknxproject /tmp/xknxproject \
 && mkdir -p /samples \
 && cp /tmp/xknx/test/secure_tests/resources/*.knxkeys /samples/ \
 && cp /tmp/xknxproject/test/resources/*.knxproj /samples/ \
 && cp -r /tmp/xknxproject/test/resources/stubs /samples/stubs \
 && rm -rf /tmp/xknx /tmp/xknxproject
COPY peer.py /peer.py
ENTRYPOINT ["python3", "/peer.py"]
