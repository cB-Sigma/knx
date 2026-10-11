# Copyright 2026 Abhinav Gautam
# SPDX-License-Identifier: Apache-2.0
"""Reads ETS keyrings with xknx and ETS projects with xknxproject and prints
what they found as JSON, for comparison with the Go module.

    peer.py keyring PATH PASSWORD
    peer.py project PATH PASSWORD

PATH "-" reads the file from standard input; PASSWORD "-" means none.
"""

import json
import os
import sys
import tempfile


def _path(arg):
    if arg != "-":
        return arg
    fd, name = tempfile.mkstemp()
    with os.fdopen(fd, "wb") as f:
        f.write(sys.stdin.buffer.read())
    return name


def keyring(path, password):
    from xknx.secure.keyring import sync_load_keyring

    k = sync_load_keyring(path, password)
    out = {"project": k.project_name, "interfaces": [], "devices": [],
           "backbone": k.backbone is not None, "group_keys": len(k.group_addresses)}
    for i in k.interfaces:
        dev = k.get_device_by_interface(i)
        out["interfaces"].append({
            "type": i.type.value,
            "ia": str(i.individual_address),
            "host": str(i.host) if i.host else "",
            "user_id": i.user_id or 0,
            "password": i.decrypted_password or "",
            "auth": i.decrypted_authentication or "",
            "host_auth": (dev.decrypted_authentication or "") if dev else "",
        })
    for d in k.devices:
        out["devices"].append({
            "ia": str(d.individual_address),
            "auth": d.decrypted_authentication or "",
            "mgmt": d.decrypted_management_password or "",
        })
    return out


def project(path, password):
    from xknxproject import XKNXProj

    p = XKNXProj(path, None if password == "-" else password).parse()
    gas = []
    for ga in p["group_addresses"].values():
        dpt = ga.get("dpt")
        gas.append({
            "address": ga["address"],
            "raw": ga["raw_address"],
            "name": ga["name"],
            "dpt": "" if not dpt else "%d.%03d" % (dpt["main"], dpt["sub"]) if dpt.get("sub") is not None else "%d" % dpt["main"],
        })
    return {"name": p["info"]["name"], "group_addresses": gas}


def main():
    cmd, path, password = sys.argv[1], _path(sys.argv[2]), sys.argv[3]
    result = keyring(path, password) if cmd == "keyring" else project(path, password)
    json.dump(result, sys.stdout, ensure_ascii=False)


if __name__ == "__main__":
    main()
