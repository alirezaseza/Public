#!/usr/bin/env python3
"""Real speed test for proxy links through sing-box. Standard library only (needs the sing-box binary).

filter_links(links) -> the links that connected AND passed the latency / speed limits,
sorted by download speed, fastest first (equal speeds keep the input order, i.e. newest first).

One sing-box process per batch, one local http/socks inbound per link (inbound N -> outbound N).
"""
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit, parse_qs, unquote

from validate_subscription import b64decode

BASE_PORT = 21000
LAT_URL = "https://www.gstatic.com/generate_204"
DL_URLS = ["https://speed.cloudflare.com/__down?bytes=1000000",
           "https://cachefly.cachefly.net/1mb.test",
           "https://proof.ovh.net/files/1Mb.dat"]
_ERR = {}


# ---------------------------------------------------------------- link -> sing-box outbound
def _transport(net, host, path, service):
    """{} = plain tcp, dict = transport, None = unsupported."""
    net = (net or "tcp").lower()
    if net == "tcp":
        return {}
    if net == "ws":
        t = {"type": "ws", "path": path or "/"}
        if host:
            t["headers"] = {"Host": host}
        return t
    if net == "grpc":
        return {"type": "grpc", "service_name": service or ""}
    if net == "httpupgrade":
        t = {"type": "httpupgrade", "path": path or "/"}
        if host:
            t["host"] = host
        return t
    if net in ("h2", "http"):
        return {"type": "http", "path": path or "/", "host": [host] if host else []}
    return None                                   # xhttp, kcp, quic ... not supported here


def _tls(sec, sni, fp, alpn, insecure, pbk, sid, server):
    if sec not in ("tls", "reality"):
        return None
    t = {"enabled": True, "server_name": sni or server, "insecure": insecure in ("1", "true", True)}
    if alpn:
        t["alpn"] = [a for a in alpn.split(",") if a]
    if fp or sec == "reality":
        t["utls"] = {"enabled": True, "fingerprint": fp or "chrome"}
    if sec == "reality":
        if not pbk:
            raise ValueError("reality without public key")
        t["reality"] = {"enabled": True, "public_key": pbk, "short_id": sid or ""}
    return t


def to_outbound(link):
    """-> sing-box outbound dict (without tag) or None if unsupported / broken."""
    try:
        low = link.lower()
        if low.startswith("vmess://"):
            j = json.loads(b64decode(link.split("://", 1)[1].split("#")[0]))
            ob = {"type": "vmess", "server": str(j["add"]), "server_port": int(str(j["port"])),
                  "uuid": j["id"], "alter_id": int(j.get("aid") or 0), "security": j.get("scy") or "auto"}
            if (j.get("type") or "none") not in ("none", ""):
                return None
            tr = _transport(j.get("net"), j.get("host"), j.get("path"), j.get("path"))
            if tr is None:
                return None
            if tr:
                ob["transport"] = tr
            tls = _tls("tls" if j.get("tls") == "tls" else "", j.get("sni") or j.get("host"),
                       j.get("fp"), j.get("alpn"), None, None, None, ob["server"])
            if tls:
                ob["tls"] = tls
            return ob

        u = urlsplit(link)
        p = {k: v[0] for k, v in parse_qs(u.query).items()}

        if low.startswith("ss://"):
            if "plugin" in p:
                return None
            if u.username and u.hostname and u.port:
                if u.password:
                    method, pw = unquote(u.username), unquote(u.password)
                else:
                    method, _, pw = b64decode(unquote(u.username)).partition(":")
                host, port = u.hostname, u.port
            else:
                raw = b64decode(link[5:].split("#")[0].split("?")[0])
                cred, _, hp = raw.rpartition("@")
                method, _, pw = cred.partition(":")
                host, _, port = hp.rpartition(":")
                host, port = host.strip("[]"), int(port)
            if not method or not pw or not host:
                return None
            return {"type": "shadowsocks", "server": host, "server_port": int(port), "method": method, "password": pw}

        if not (u.hostname and u.port and u.username):
            return None
        ob = {"type": "vless" if low.startswith("vless://") else "trojan",
              "server": u.hostname, "server_port": u.port}
        if ob["type"] == "vless":
            ob["uuid"] = unquote(u.username)
            if p.get("flow"):
                ob["flow"] = p["flow"]
        else:
            ob["password"] = unquote(u.username)
        net = p.get("type", "tcp")
        if net == "tcp" and p.get("headerType") == "http":
            return None
        tr = _transport(net, p.get("host"), p.get("path"), p.get("serviceName"))
        if tr is None:
            return None
        if tr:
            ob["transport"] = tr
        sec = p.get("security", "tls" if ob["type"] == "trojan" else "none")
        tls = _tls(sec, p.get("sni") or p.get("peer"), p.get("fp"), p.get("alpn"),
                   p.get("allowInsecure") or p.get("insecure"), p.get("pbk"), p.get("sid"), ob["server"])
        if tls:
            ob["tls"] = tls
        return ob
    except Exception:
        return None


# ---------------------------------------------------------------- sing-box process
def _binary():
    return os.environ.get("SINGBOX") or shutil.which("sing-box")


def _start(binary, outs):
    """-> (process, "") when every inbound is listening, else (None, sing-box error text)."""
    cfg = {
        "log": {"level": "error"},
        "inbounds": [{"type": "mixed", "tag": f"in{i}", "listen": "127.0.0.1", "listen_port": BASE_PORT + i}
                     for i in range(len(outs))],
        "outbounds": [dict(o, tag=f"out{i}") for i, o in enumerate(outs)] + [{"type": "direct", "tag": "direct"}],
        "route": {"rules": [{"inbound": [f"in{i}"], "outbound": f"out{i}"} for i in range(len(outs))],
                  "final": "direct"},
    }
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(cfg, f)
    err = tempfile.TemporaryFile()
    proc = subprocess.Popen([binary, "run", "-c", path], stdout=subprocess.DEVNULL, stderr=err)
    last = BASE_PORT + len(outs) - 1
    end = time.time() + 25
    try:
        while time.time() < end and proc.poll() is None:
            try:                                   # sing-box opens inbounds only after all outbounds initialised
                socket.create_connection(("127.0.0.1", last), timeout=0.3).close()
                return proc, ""
            except OSError:
                time.sleep(0.2)
        if proc.poll() is None:
            proc.kill()
        proc.wait()
        err.seek(0)
        return None, err.read().decode("utf-8", "replace")
    finally:
        os.unlink(path)
        err.close()


def _bad_index(err, n):
    """Which outbound sing-box complained about, if its message says."""
    m = re.search(r"\[out(\d+)\]|outbound\[(\d+)\]", err)
    if m:
        i = int(m.group(1) or m.group(2))
        if 0 <= i < n:
            return i
    return None


def _opener(port):
    px = f"http://127.0.0.1:{port}"
    return urllib.request.build_opener(urllib.request.ProxyHandler({"http": px, "https": px}))


def _latency(port, timeout=6):
    t = time.time()
    try:
        with _opener(port).open(urllib.request.Request(LAT_URL), timeout=timeout) as r:
            r.read(16)
        return (time.time() - t) * 1000
    except Exception:
        return None


def _speed(port, deadline=6):
    """Mbit/s of a small download; tries several hosts; the clock starts once the headers are in."""
    for url in DL_URLS:
        got, t = 0, None
        try:
            with _opener(port).open(urllib.request.Request(url), timeout=8) as r:
                t = time.time()
                while time.time() - t < deadline:
                    b = r.read(65536)
                    if not b:
                        break
                    got += len(b)
        except Exception as e:
            k = repr(e)[:70]
            _ERR[k] = _ERR.get(k, 0) + 1
        if got and t is not None:
            return got * 8 / 1e6 / max(time.time() - t, 0.05)
    return 0.0


def _run(binary, items, max_ms, min_mbps):
    """items = [(link, outbound)] -> [(mbps, ms, link)] of those that passed."""
    proc = None
    while items:
        proc, err = _start(binary, [o for _, o in items])
        if proc:
            break
        bad = _bad_index(err, len(items))
        if bad is not None:                        # sing-box named the broken outbound: drop it, retry
            items = items[:bad] + items[bad + 1:]
            continue
        if len(items) == 1:
            return []
        h = len(items) // 2                        # unknown error: bisect to isolate the broken link
        return _run(binary, items[:h], max_ms, min_mbps) + _run(binary, items[h:], max_ms, min_mbps)
    if not proc:
        return []
    try:
        ports = [BASE_PORT + i for i in range(len(items))]
        with ThreadPoolExecutor(32) as ex:
            lat = list(ex.map(_latency, ports))
        ok = [i for i, ms in enumerate(lat) if ms is not None and ms <= max_ms]
        with ThreadPoolExecutor(8) as ex:          # limited so the tests do not steal each other's bandwidth
            sp = list(ex.map(lambda i: _speed(ports[i]), ok))
        if _ERR:
            print('  speed errors:', sorted(_ERR.items(), key=lambda x: -x[1])[:4])
        print(f'  batch: {len(items)} started, {len(ok)} latency ok, {sum(1 for s in sp if s > 0)} got data')
        return [(s, lat[i], items[i][0]) for i, s in zip(ok, sp) if s >= min_mbps]
    finally:
        proc.terminate()
        try:
            proc.wait(5)
        except Exception:
            proc.kill()


def filter_links(links, min_mbps=0.5, max_ms=4000, budget_s=2400, batch=100):
    binary = _binary()
    if not binary:
        print("::warning::sing-box not found - speed test skipped")
        return links
    t0, passed, tested = time.time(), {}, 0
    items = [(l, o) for l in links for o in [to_outbound(l)] if o]
    print(f"speed test: {len(items)}/{len(links)} links convertible to sing-box")
    for i in range(0, len(items), batch):          # items are newest-first, so the freshest get tested first
        if time.time() - t0 > budget_s:
            print(f"speed test: time budget reached, {len(items) - tested} older links left untested (dropped)")
            break
        part = items[i:i + batch]
        passed.update({l: mbps for mbps, _, l in _run(binary, part, max_ms, min_mbps)})
        tested += len(part)
        print(f"  tested {tested}/{len(items)}, passed so far {len(passed)}")
    print(f"speed test: {len(passed)} passed (>= {min_mbps:g} Mbit/s, <= {max_ms} ms)")
    fast = [l for l, _ in items if l in passed]    # input order = newest first
    fast.sort(key=lambda l: -passed[l])            # stable sort: fastest first, ties stay newest first
    return fast
