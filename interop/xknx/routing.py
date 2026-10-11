# Copyright 2026 Abhinav Gautam
# SPDX-License-Identifier: Apache-2.0
"""Routing interop driver: starts this module's routepeer (a Linux build
mounted at /peer) and xknx in the same container, on the same multicast
group, and prints what each side saw:

    PEER <line of routepeer>
    CONNECTED <individual address>
    TELEGRAM <source> <group address> <service> <hex value>
    READ <group address> <hex value>
    DONE

    routing.py plain|secure KEYRING PASSWORD
"""

import asyncio
import socket
import sys

from xknx import XKNX
from xknx.core.value_reader import ValueReader
from xknx.dpt import DPTArray, DPTBinary
from xknx.io import ConnectionConfig, ConnectionType, SecureConfig
from xknx.telegram import GroupAddress, Telegram
from xknx.telegram.apci import GroupValueWrite


def say(*parts):
    print(*parts, flush=True)


def hexval(payload):
    v = getattr(payload, "value", None)
    if isinstance(v, DPTBinary):
        return "%02x" % v.value
    if isinstance(v, DPTArray):
        return bytes(v.value).hex()
    return ""


async def main(mode, keyring, password):
    # "secure-late" starts xknx first, so that it keeps the time and this
    # module synchronises to it.
    secure = mode.startswith("secure")
    args = ["/peer/routepeer", "-keyring", keyring, "-password", password, "-source", "4.0.9"]
    if secure:
        args.append("-secure")
    ready = asyncio.Event()
    peer = None
    pumper = None

    async def start_peer():
        nonlocal peer, pumper
        peer = await asyncio.create_subprocess_exec(*args, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE)

        async def pump():
            while line := await peer.stdout.readline():
                text = line.decode().rstrip()
                say("PEER", text)
                if text.startswith("READY") or text.startswith("ERROR"):
                    ready.set()

        pumper = asyncio.create_task(pump())
        await asyncio.wait_for(ready.wait(), 20)

    if mode != "secure-late":
        await start_peer()

    local_ip = socket.gethostbyname(socket.gethostname())
    cfg = ConnectionConfig(
        connection_type=ConnectionType.ROUTING_SECURE if secure else ConnectionType.ROUTING,
        local_ip=local_ip, individual_address="5.0.1",
        secure_config=SecureConfig(knxkeys_file_path=keyring, knxkeys_password=password))

    def received(t):
        say("TELEGRAM", t.source_address, t.destination_address, type(t.payload).__name__, hexval(t.payload))

    xknx = XKNX(connection_config=cfg, telegram_received_cb=received)
    await xknx.start()
    say("CONNECTED", xknx.current_address)
    if mode == "secure-late":
        await start_peer()
    await xknx.telegrams.put(Telegram(destination_address=GroupAddress("1/1/7"), payload=GroupValueWrite(DPTBinary(1))))
    await xknx.telegrams.put(Telegram(destination_address=GroupAddress("0/4/0"), payload=GroupValueWrite(DPTArray((0x0C, 0x1A)))))
    await asyncio.sleep(1)
    peer.stdin.write(b"SEND 1/1/8 01 short\nSEND 0/4/3 0c33 long\n")
    await peer.stdin.drain()
    reply = await ValueReader(xknx, GroupAddress("1/2/3"), timeout_in_seconds=5).read()
    say("READ", "1/2/3", hexval(reply.payload) if reply else "none")
    await asyncio.sleep(2)
    await xknx.stop()
    peer.stdin.close()
    await asyncio.wait_for(peer.wait(), 10)
    await pumper
    say("DONE")


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1], sys.argv[2], sys.argv[3]))
