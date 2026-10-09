#!/usr/bin/env python3
"""Health-check vless:// URIs with Xray and emit only the healthy ones."""

import argparse
import json
import os
import re
import socket
import subprocess
import tempfile
import time
import urllib.parse
from pathlib import Path

XRAY = os.environ.get("XRAY", os.path.expanduser("~/xray/xray"))
TEST_URL = os.environ.get("TEST_URL", "http://www.gstatic.com/generate_204")
PER_TEST = int(os.environ.get("PER_TEST", "12"))
OK_CODES = {"200", "204", "301", "302", "307", "308"}

URI_RE = re.compile(
    r"^vless://(?P<uuid>[^@]+)@(?P<addr>[^:/?#]+):(?P<port>\d+)"
    r"(?:\?(?P<qs>[^#]*))?(?:#(?P<frag>.*))?$"
)


def parse(uri: str):
    m = URI_RE.match(uri.strip())
    if not m:
        return None
    q = urllib.parse.parse_qs(m.group("qs") or "", keep_blank_values=True)
    get = lambda k, d="": (q.get(k, [""])[0] or d)
    return {
        "uri": uri.strip(),
        "uuid": m.group("uuid"),
        "address": m.group("addr"),
        "port": int(m.group("port")),
        "flow": get("flow"),
        "security": get("security", "none"),
        "network": get("type", "tcp"),
        "sni": get("sni") or m.group("addr"),
        "fp": get("fp") or "chrome",
        "pbk": get("pbk"),
        "sid": get("sid"),
        "authority": get("authority") or get("host"),
        "serviceName": get("serviceName"),
        "path": get("path") or "/",
        "label": urllib.parse.unquote(m.group("frag") or "") or m.group("addr"),
        "endpoint": f"{m.group('addr')}:{m.group('port')}",
    }


def build_client(e, port: int) -> dict:
    stream = {"network": e["network"]}
    if e["security"] == "reality":
        stream["security"] = "reality"
        stream["realitySettings"] = {
            "serverName": e["sni"],
            "fingerprint": e["fp"],
            "publicKey": e["pbk"],
            "shortId": e["sid"],
            "spiderX": "/",
        }
    elif e["security"] == "tls":
        stream["security"] = "tls"
        stream["tlsSettings"] = {"serverName": e["sni"], "fingerprint": e["fp"]}

    if e["network"] == "grpc":
        stream["grpcSettings"] = {"serviceName": e["serviceName"] or e["authority"]}
    elif e["network"] == "ws":
        stream["wsSettings"] = {"path": e["path"], "host": e["authority"]}
    else:
        stream["tcpSettings"] = {"header": {"type": "none"}}

    return {
        "log": {"loglevel": "none"},
        "inbounds": [
            {
                "port": port,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"udp": False},
            }
        ],
        "outbounds": [
            {
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": e["address"],
                            "port": e["port"],
                            "users": [
                                {
                                    "id": e["uuid"],
                                    "encryption": "none",
                                    "flow": e["flow"],
                                }
                            ],
                        }
                    ]
                },
                "streamSettings": stream,
            }
        ],
    }


def probe(e, port: int):
    cfg = build_client(e, port)
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    Path(path).write_text(json.dumps(cfg), encoding="utf-8")

    proc = subprocess.Popen(
        [XRAY, "run", "-c", path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(40):
            try:
                with socket.create_connection(("127.0.0.1", port), 0.25):
                    break
            except OSError:
                time.sleep(0.25)
        else:
            return False, "inbound-never-listened"

        r = subprocess.run(
            [
                "curl",
                "-sS",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "-x",
                f"socks5h://127.0.0.1:{port}",
                "--max-time",
                str(PER_TEST),
                TEST_URL,
            ],
            capture_output=True,
            text=True,
        )
        code = (r.stdout or "").strip()
        if code in OK_CODES:
            return True, code
        return False, code or (r.stderr or "").strip().splitlines()[-1][:70] if r.stderr else "no-code"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        os.unlink(path)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--extra", action="append", default=[])
    ap.add_argument("--out", required=True)
    ap.add_argument("--report", required=True)
    ap.add_argument("--port-base", type=int, default=21000)
    args = ap.parse_args()

    uris = []
    for f in args.files:
        uris += [
            ln.strip()
            for ln in Path(f).read_text(encoding="utf-8").splitlines()
            if ln.strip().startswith("vless://")
        ]
    uris += args.extra

    seen, ordered = set(), []
    for u in uris:
        if u not in seen:
            seen.add(u)
            ordered.append(u)

    healthy, lines = [], []
    for i, uri in enumerate(ordered):
        e = parse(uri)
        if e is None:
            lines.append(f"FAIL  (unparseable)  {uri[:80]}")
            continue
        ok, detail = probe(e, args.port_base + i)
        tag = "OK  " if ok else "FAIL"
        lines.append(f"{tag}  {e['endpoint']:<28} {e['network']:<5} {detail}")
        print(f"{tag}  {e['endpoint']:<28} {e['network']:<5} {detail}", flush=True)
        if ok:
            healthy.append(uri)

    Path(args.out).write_text(
        "\n".join(healthy) + ("\n" if healthy else ""), encoding="utf-8"
    )
    Path(args.report).write_text(
        f"generated: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n"
        f"total: {len(ordered)}   healthy: {len(healthy)}\n\n" + "\n".join(lines) + "\n",
        encoding="utf-8",
    )
    print(f"\nhealthy {len(healthy)}/{len(ordered)} -> {args.out}", flush=True)
    if not healthy:
        print("::warning::no healthy config found")


if __name__ == "__main__":
    main()
