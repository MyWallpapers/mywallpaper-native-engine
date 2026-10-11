"""Reusable Windows fixture qualification using the public process-v2 contract.

For add-ons with other targets, supply an add-on-owned fixture/test suite instead
of pretending these integer checks establish Explorer or XAML compatibility.
"""
import argparse
import hashlib
import json
import os
import pathlib
import queue
import struct
import subprocess
import threading
import time


def wait(check, label, seconds=15):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        value = check()
        if value:
            return value
        time.sleep(0.02)
    raise AssertionError("timeout: " + label)


class Fixture:
    def __init__(self, executable):
        self.process = subprocess.Popen([str(executable)], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, creationflags=0x08000000)
        self.lines = queue.Queue()
        def read():
            for line in iter(self.process.stdout.readline, b""):
                self.lines.put(json.loads(line))
        threading.Thread(target=read, daemon=True).start()
        self.pid = self.lines.get(timeout=10)["pid"]

    def request(self, command="sample"):
        self.process.stdin.write((command + "\n").encode())
        self.process.stdin.flush()
        return self.lines.get(timeout=10)

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.write(b"quit\n")
            self.process.stdin.flush()
            self.process.wait(timeout=10)
        assert self.process.returncode == 0


class Controller:
    def __init__(self, launcher, bundle, home, architecture, settings, scratch):
        environment = {**os.environ, "MW_NATIVE_ENGINE_HOME": str(home), "LOCALAPPDATA": str(scratch / "localappdata")}
        self.process = subprocess.Popen([str(launcher), "--bundle", str(bundle)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=environment, creationflags=0x08000000)
        self.stopping = False
        self.frames = queue.Queue()
        self.diagnostics = []
        def read_exact(length):
            value = bytearray()
            while len(value) < length:
                chunk = self.process.stdout.read(length - len(value))
                if not chunk:
                    raise EOFError("controller stdout ended")
                value.extend(chunk)
            return value
        def read():
            try:
                record = bytearray()
                while True:
                    raw, = struct.unpack("<I", read_exact(4))
                    kind, length = raw >> 30, raw & 0x3fffffff
                    assert 0 < length <= 1024 * 1024
                    data = read_exact(length)
                    if kind == 0:
                        assert not record
                        self.frames.put(json.loads(data))
                    elif kind == 1:
                        assert not record
                        record.extend(data)
                    else:
                        assert record and kind in (2, 3)
                        record.extend(data)
                        if kind == 3:
                            self.frames.put(json.loads(record))
                            record.clear()
            except Exception as error:
                self.frames.put(error)
        def errors():
            for line in iter(self.process.stderr.readline, b""):
                text = line.decode("utf-8", errors="replace").strip()
                try:
                    self.diagnostics.append(json.loads(text))
                except json.JSONDecodeError:
                    self.diagnostics.append({"message": text})
        threading.Thread(target=read, daemon=True).start()
        threading.Thread(target=errors, daemon=True).start()
        digest = hashlib.sha256((bundle / "addon.dll").read_bytes()).hexdigest()
        self.send({"type": "init", "v": 5, "addonId": "development:native-sdk-example",
            "artifactDigest": "sha256:" + digest, "version": "0.1.0",
            "targetArchitecture": architecture, "scratchDirectory": str(scratch),
            "layerSettings": {}, "deviceSettings": settings})

    def send(self, record):
        if record["type"] == "shutdown":
            self.stopping = True
        data = json.dumps(record).encode()
        self.process.stdin.write(struct.pack("<I", len(data)) + data)
        self.process.stdin.flush()

    def ready(self):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            frame = self.frames.get(timeout=max(0.01, deadline - time.monotonic()))
            assert not isinstance(frame, Exception), (frame, self.diagnostics)
            assert frame["type"] != "error", frame
            if frame["type"] == "ready":
                return
        raise AssertionError("controller never became ready")

    def settings(self, value):
        self.send({"type": "settings", "v": 5, "layerSettings": {}, "deviceSettings": value})

    def stop(self):
        if self.process.poll() is None:
            if not self.stopping:
                self.send({"type": "shutdown", "v": 5})
            self.process.wait(timeout=15)
        assert self.process.returncode == 0, self.diagnostics

    def kill(self):
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=10)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", type=pathlib.Path, required=True)
    parser.add_argument("--engine", type=pathlib.Path, required=True)
    parser.add_argument("--fixture", type=pathlib.Path, required=True)
    parser.add_argument("--architecture", choices=["x64", "x86", "arm64"], default="x64")
    parser.add_argument("--cycles", type=int, default=100)
    parser.add_argument("--settings", type=json.loads, default={"enabled": True, "delta": 7})
    parser.add_argument("--updated-settings", type=json.loads, default={"enabled": True, "delta": 12})
    parser.add_argument("--expected", type=int, default=17)
    parser.add_argument("--updated-expected", type=int, default=22)
    parser.add_argument("--check-symbol-recovery", action="store_true",
                        help="SDK example only: temporarily move its local PDB and verify recovery")
    args = parser.parse_args()
    assert 1 <= args.cycles
    bundle, engine = args.bundle.resolve(), args.engine.resolve()
    fixture = None
    controllers = []
    saved_pdb = None
    architecture = {"x64": "windows-x86_64", "x86": "windows-x86", "arm64": "windows-arm64"}[args.architecture]
    scratch = bundle.parent / "qualification-scratch"
    scratch.mkdir(exist_ok=True)
    def start(ready=True):
        controller = Controller(bundle / "companion.exe", bundle, engine, architecture, args.settings, scratch)
        controllers.append(controller)
        if ready:
            controller.ready()
        return controller
    try:
        fixture = Fixture(args.fixture.resolve())
        baseline = fixture.request()["value"]
        if args.check_symbol_recovery:
            pdb = args.fixture.resolve().with_suffix(".pdb")
            saved_pdb = pdb.with_suffix(".qualification-saved.pdb")
            assert pdb.is_file() and not saved_pdb.exists()
            pdb.rename(saved_pdb)
            controller = start(ready=False)
            wait(lambda: any(d.get("code") == "symbol_unavailable" for d in controller.diagnostics), "PDB availability diagnostic")
            assert controller.process.poll() is None
            assert not any(d.get("code") == "symbol_absent" for d in controller.diagnostics)
            saved_pdb.rename(pdb)
            saved_pdb = None
            controller.ready()
            wait(lambda: any(d.get("code") == "symbol_absent" for d in controller.diagnostics), "confirmed exact absence")
        else:
            controller = start()
        wait(lambda: fixture.request()["value"] == args.expected, "initial effect")
        controller.settings(args.updated_settings)
        wait(lambda: fixture.request()["value"] == args.updated_expected, "live settings")
        controller.settings({"enabled": True, "delta": "invalid"})
        wait(lambda: any(d.get("code") == "addon_settings_rejected" for d in controller.diagnostics), "nonfatal settings rejection")
        assert controller.process.poll() is None
        assert fixture.request()["value"] == args.updated_expected
        fixture.request("hold")
        wait(lambda: fixture.request("state")["entered"], "entered callback")
        controller.send({"type": "shutdown", "v": 5})
        time.sleep(0.06)
        assert controller.process.poll() is None, ("stop failed to wait for an entered call", controller.process.returncode, controller.diagnostics)
        fixture.request("release")
        controller.stop()
        wait(lambda: fixture.request()["value"] == baseline, "cooperative stop")
        controller = start()
        controller.kill()
        wait(lambda: fixture.request()["value"] == baseline, "owner death")
        # Reuse the same DLL, identity and scratch. New arbitrary versions are
        # intentionally outside this plateau measurement.
        for _ in range(5):
            controller = start(); controller.stop()
        before = fixture.request()["privateBytes"]
        for _ in range(args.cycles):
            controller = start()
            assert fixture.request()["value"] == args.expected
            controller.stop()
            assert fixture.request()["value"] == baseline
        after = fixture.request()["privateBytes"]
        controller = start()
        fixture.close()
        fixture = Fixture(args.fixture.resolve())
        wait(lambda: fixture.request()["value"] == args.expected, "target restart")
        controller.stop()
        assert fixture.request()["value"] == baseline
        print(json.dumps({"passed": True, "architecture": args.architecture,
            "cycles": args.cycles, "settings": True, "rejectionIsNonfatal": True,
            "enteredCallDrained": True, "ownerDeath": True, "targetRestart": True,
            "symbolAvailabilityRecovery": args.check_symbol_recovery,
            "privateBytesBefore": before, "privateBytesAfter": after,
            "privateBytesDelta": after - before}, indent=2))
    finally:
        if saved_pdb and saved_pdb.exists():
            saved_pdb.rename(args.fixture.resolve().with_suffix(".pdb"))
        for controller in controllers:
            controller.kill()
        if fixture:
            fixture.close()


if __name__ == "__main__":
    main()
