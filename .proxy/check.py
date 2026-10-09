#!/usr/bin/env python3
"""Test vless:// URIs by chaining them behind a local socks inbound."""

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
TEST_URL = os.environ.get("TEST_URL", "https://www.gstatic.com/generate_204")
PER_TEST = int(os.environ.get("PER_TEST", "12"))
OK_CODES = {"200", "204", "301", "302", "307", "308"}
TUNNEL_UUID = "ca52e2b6-fb9f-4dac-b6dc-49da9923f251"

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


def build_outbound(e) -> dict:
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
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": e["address"],
                    "port": e["port"],
                    "users": [
                        {"id": e["uuid"], "encryption": "none", "flow": e["flow"]}
                    ],
                }
            ]
        },
        "streamSettings": stream,
    }


def probe(e, port: int):
    cfg = {
        "log": {"loglevel": "none"},
        "inbounds": [
            {
                "port": port,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"udp": False},
            }
        ],
        "outbounds": [build_outbound(e)],
    }
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
            return False, "xray-inbound-dead", 0.0

        t0 = time.time()
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
        dt = time.time() - t0
        code = (r.stdout or "").strip()
        err = (r.stderr or "").strip().splitlines()
        why = err[-1][:70] if err else ""
        if code in OK_CODES:
            return True, f"http {code}", dt
        return False, f"http {code} {why}".strip(), dt
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        os.unlink(path)


def emit_server(uri, out_path, listen, port, mode="ws", reality=None):
    e = parse(uri)
    if e is None:
        raise SystemExit(f"cannot parse: {uri}")

    if mode == "reality":
        if not reality or not reality.get("private") or not reality.get("sid"):
            raise SystemExit("--emit-mode reality requires --emit-private and --emit-sid")
        sni = reality.get("sni") or "addons.mozilla.org"
        inbound = {
            "tag": "public-reality",
            "port": port,
            "listen": listen,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {"id": TUNNEL_UUID, "flow": "xtls-rprx-vision", "level": 0}
                ],
                "decryption": "none",
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": False,
                    "dest": f"{sni}:443",
                    "xver": 0,
                    "serverNames": [sni],
                    "privateKey": reality["private"],
                    "shortIds": [reality["sid"]],
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        }
    else:
        inbound = {
            "tag": "public-ws",
            "port": port,
            "listen": listen,
            "protocol": "vless",
            "settings": {
                "clients": [{"id": TUNNEL_UUID, "flow": "", "level": 0}],
                "decryption": "none",
            },
            "streamSettings": {
                "network": "ws",
                "security": "none",
                "wsSettings": {"path": "/"},
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        }

    cfg = {
        "log": {"loglevel": "warning"},
        "inbounds": [inbound],
        "outbounds": [build_outbound(e)],
    }
    Path(out_path).write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    print(f"server config -> {out_path}  (mode={mode}, upstream {e['endpoint']} {e['network']})")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="*")
    ap.add_argument("--extra", action="append", default=[])
    ap.add_argument("--out")
    ap.add_argument("--report")
    ap.add_argument("--port-base", type=int, default=21000)
    ap.add_argument("--emit-server")
    ap.add_argument("--emit-out")
    ap.add_argument("--emit-listen", default="0.0.0.0")
    ap.add_argument("--emit-port", type=int, default=10000)
    ap.add_argument("--emit-mode", choices=["ws", "reality"], default="ws")
    ap.add_argument("--emit-private")
    ap.add_argument("--emit-sid")
    ap.add_argument("--emit-sni", default="addons.mozilla.org")
    args = ap.parse_args()

    if args.emit_server:
        if not args.emit_out:
            raise SystemExit("--emit-server requires --emit-out")
        reality = {
            "private": args.emit_private,
            "sid": args.emit_sid,
            "sni": args.emit_sni,
        }
        emit_server(
            args.emit_server,
            args.emit_out,
            args.emit_listen,
            args.emit_port,
            args.emit_mode,
            reality if args.emit_mode == "reality" else None,
        )
        return

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
            lines.append(f"FAIL  {'unparseable':<34} {uri[:70]}")
            continue
        ok, detail, dt = probe(e, args.port_base + i)
        tag = "OK  " if ok else "FAIL"
        row = f"{tag}  {e['endpoint']:<34} {e['network']}/{e['security']:<8} {detail:<10} {dt:5.2f}s"
        lines.append(row)
        print(row, flush=True)
        if ok:
            healthy.append((dt, uri, e["endpoint"]))

    healthy.sort(key=lambda x: x[0])
    uris_sorted = [u for _, u, _ in healthy]

    if healthy:
        lines.append("")
        lines.append("fastest first:")
        for dt, _, ep in healthy[:5]:
            lines.append(f"  {dt:5.2f}s  {ep}")

    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(
            "\n".join(uris_sorted) + ("\n" if uris_sorted else ""), encoding="utf-8"
        )
    if args.report:
        Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report).write_text(
            f"generated: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n"
            f"total: {len(ordered)}   healthy: {len(uris_sorted)}\n\n" + "\n".join(lines) + "\n",
            encoding="utf-8",
        )
    print(f"\nhealthy {len(uris_sorted)}/{len(ordered)}", flush=True)
    if not uris_sorted:
        print("::warning::no healthy upstream found")


if __name__ == "__main__":
    main()
