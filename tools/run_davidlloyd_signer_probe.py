#!/usr/bin/env python3
"""Attach the privacy-preserving signer probe to the running Android app."""

from __future__ import annotations

import json
import os
import signal
from pathlib import Path

import frida


PACKAGE_NAME = "co.uk.davidlloyd.mobileapp"
FRIDA_ENDPOINT = "127.0.0.1:27042"
SCRIPT_PATH = Path(
    os.environ.get(
        "DAVID_LLOYD_FRIDA_SCRIPT",
        Path(__file__).with_name("davidlloyd_signer_probe.js"),
    )
)


def on_message(message: dict, data: bytes | None) -> None:
    del data
    if message.get("type") == "send":
        print(json.dumps(message["payload"], ensure_ascii=False), flush=True)
    else:
        safe = {
            "type": message.get("type", "unknown"),
            "description": message.get("description", "Frida script error"),
        }
        print(json.dumps(safe, ensure_ascii=False), flush=True)


def on_detached(reason: str, crash: object | None) -> None:
    print(
        json.dumps(
            {
                "kind": "host-detached",
                "reason": reason,
                "crash": crash is not None,
            }
        ),
        flush=True,
    )


def main() -> None:
    manager = frida.get_device_manager()
    device = manager.add_remote_device(FRIDA_ENDPOINT)
    process = next(
        (
            process
            for process in device.enumerate_processes()
            if process.name == "David Lloyd Clubs"
        ),
        None,
    )
    spawned = process is None
    pid = device.spawn([PACKAGE_NAME]) if spawned else process.pid
    session = device.attach(pid)
    session.on("detached", on_detached)
    script = session.create_script(SCRIPT_PATH.read_text(encoding="utf-8"))
    script.on("message", on_message)
    script.load()
    if spawned:
        device.resume(pid)
    print(
        json.dumps(
            {
                "kind": "host-ready",
                "pid": pid,
                "package": PACKAGE_NAME,
                "spawned": spawned,
            }
        ),
        flush=True,
    )
    signal.pause()


if __name__ == "__main__":
    main()
