#!/usr/bin/env python3
"""Collect proxy configs from public Telegram channels and write the subscription file the app reads.

Runs inside GitHub Actions (no bot, no server). Stateless: every run rebuilds the file from scratch,
so anything posted more than --max-age hours ago (default 25) disappears automatically.

Usage: collect_configs.py [--channels channels.txt] [-o sub/all.txt] [--max-age 25]
Standard library only.
"""
import argparse
import html
import ipaddress
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from validate_subscription import b64decode, check  # same rules the app uses: drops links it cannot run

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36"
LINK_RE = re.compile(r"(?<![A-Za-z0-9])(?:vless|vmess|trojan|ss)://[^\s<>\"'`]+", re.I)
MSG_RE = re.compile(r'<div class="tgme_widget_message_wrap.*?(?=<div class="tgme_widget_message_wrap|\Z)', re.S)
TIME_RE = re.compile(r'<time[^>]*datetime="([^"]+)"')
ID_RE = re.compile(r'data-post="[^"/]+/(\d+)"')
TEXT_RE = re.compile(r'<div class="tgme_widget_message_text js-message_text[^>]*>(.*?)</div>', re.S)   # NOT the quoted reply preview (js-message_reply_text)


def fetch(url, tries=3):
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=25) as r:
                return r.read().decode("utf-8", "replace")
        except Exception as e:
            if i == tries - 1:
                print(f"  fetch failed {url}: {e.__class__.__name__}", file=sys.stderr)
            wait = 2 * (i + 1)
            if isinstance(e, urllib.error.HTTPError) and e.code == 429:
                try:
                    wait = min(30, int(e.headers.get("Retry-After", "10")))
                except ValueError:
                    wait = 10
            time.sleep(wait)
    return ""


def parse_page(page):
    """-> [(message_id, unix_time, [links])] for one t.me/s page."""
    out = []
    for blk in MSG_RE.findall(page):
        mid, tm = ID_RE.search(blk), TIME_RE.search(blk)
        if not mid or not tm:
            continue
        try:
            ts = datetime.fromisoformat(tm.group(1)).astimezone(timezone.utc).timestamp()
        except ValueError:
            continue
        links = []
        for t in TEXT_RE.findall(blk):
            t = re.sub(r"<br\s*/?>", "\n", t)
            t = html.unescape(re.sub(r"<[^>]+>", "", t))
            links += [l.rstrip(".,;)") for l in LINK_RE.findall(t)]
        out.append((int(mid.group(1)), ts, links))
    return out


def scrape(channel, cutoff, max_pages=25):
    """-> ([(unix_time, link)] posted after `cutoff`, reachable). reachable=False only when t.me itself could not be fetched."""
    found, before, reachable = [], None, True
    for _ in range(max_pages):
        page = fetch(f"https://t.me/s/{channel}" + (f"?before={before}" if before else ""))
        if not page:
            reachable = before is not None                     # first page failing = network problem, later page = just stop
            break
        msgs = parse_page(page)
        if not msgs:
            if before is None:
                print(f"  {channel}: no readable messages (preview disabled or channel missing)")
            break
        for _, ts, links in msgs:
            if ts >= cutoff:
                found += [(ts, l) for l in links]
        if min(ts for _, ts, _ in msgs) < cutoff:              # reached the end of the window
            break
        nxt = min(i for i, _, _ in msgs)
        if before is not None and nxt >= before:               # page did not move back -> avoid looping
            break
        before = nxt
        time.sleep(0.6)
    return found, reachable


def host_port(link):
    """(host, port) of a link, or None."""
    try:
        if link.lower().startswith("vmess://"):
            import json
            j = json.loads(b64decode(link.split("://", 1)[1].split("#")[0]))
            return str(j["add"]), int(str(j["port"]))
        u = urlsplit(link)
        if u.hostname and u.port:
            return u.hostname, u.port
        if link.lower().startswith("ss://"):                  # ss://BASE64(method:pw@host:port)
            raw = b64decode(link[5:].split("#")[0].split("?")[0])
            if raw and "@" in raw:
                h, _, p = raw.rsplit("@", 1)[1].rpartition(":")
                return h.strip("[]"), int(p)
    except Exception:
        pass
    return None


def _is_private(host):
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return host.lower() in ("localhost", "localhost.localdomain")
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified


def tcp_alive(hp, timeout=4.0):
    if hp is None:
        return True                                           # cannot tell -> keep it
    if _is_private(hp[0]):
        return False                                          # junk link (127.0.0.1, 192.168.x ...): useless for everyone, and the runner must not probe internal addresses
    for _ in range(2):
        try:
            with socket.create_connection(hp, timeout=timeout):
                return True
        except OSError:
            time.sleep(0.5)
    return False


def ping_filter(links, workers=128):
    hps = [host_port(l) for l in links]
    uniq = sorted({h for h in hps if h})                      # many configs share one server: test each host:port once
    with ThreadPoolExecutor(workers) as ex:
        res = dict(zip(uniq, ex.map(tcp_alive, uniq)))
    alive = [l for l, h in zip(links, hps) if h is None or res.get(h)]
    if len(alive) < 0.05 * len(links):                        # nearly everything failed = the runner's network is the problem
        print("ping test looks broken (>95% failed) - reachability filter ignored", file=sys.stderr)
        return [l for l, h in zip(links, hps) if h is None or not _is_private(h[0])]   # still never publish local/private addresses
    print(f"ping test: {len(alive)} alive, {len(links) - len(alive)} unreachable removed")
    return alive


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--channels", default="channels.txt")
    ap.add_argument("-o", "--output", default="sub/all.txt")
    ap.add_argument("--max", type=int, default=3000, help="keep at most N links (newest first), 0 = all")
    ap.add_argument("--no-ping", action="store_true", help="skip the quick TCP reachability test")
    ap.add_argument("--max-age", type=float, default=25.0, help="hours")
    a = ap.parse_args()

    cutoff = time.time() - a.max_age * 3600
    names, have = [], set()
    for l in open(a.channels, encoding="utf-8"):
        l = l.strip()
        if not l or l.startswith("#"):
            continue
        n = re.sub(r"^(?:https?://)?(?:www\.)?(?:t\.me/|telegram\.me/)?(?:s/)?@?", "", l, flags=re.I)
        n = re.split(r"[/?#\s]", n, 1)[0]
        if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{3,}", n) and n.lower() not in have:
            have.add(n.lower())
            names.append(n)
    rows, unreachable = [], 0
    with ThreadPoolExecutor(6) as ex:                  # several channels at once -> the whole run takes a few minutes
        for ch, (got, ok) in zip(names, ex.map(lambda c: scrape(c, cutoff), names)):
            print(f"{ch}: {len(got)} links in last {a.max_age:g}h" + ("" if ok else "  (t.me NOT reachable)"))
            rows += got
            unreachable += (not ok)
    if names and unreachable > len(names) / 2:         # t.me / the runner network is failing: a half-empty list would wipe good configs
        print(f"::warning::{unreachable}/{len(names)} channels unreachable - file left as is")
        sys.exit(0)

    rows.sort(key=lambda x: -x[0])                     # newest first
    seen, kept, dropped = set(), [], 0
    for _, link in rows:
        key, _why = check(link)
        if key is None or key in seen:
            dropped += 1
            continue
        seen.add(key)
        kept.append(link)
    print(f"total {len(rows)} links, kept {len(kept)}, dropped {dropped}")
    if kept and not a.no_ping:
        kept = ping_filter(kept)
    if a.max:
        kept = kept[: a.max]

    if not kept:                                       # never wipe the app's list because of a bad run (Telegram down etc.)
        print("nothing collected - leaving the existing file untouched", file=sys.stderr)
        sys.exit(0)
    os.makedirs(os.path.dirname(a.output) or ".", exist_ok=True)
    with open(a.output, "w", encoding="utf-8") as f:
        f.write("\n".join(kept) + "\n")


if __name__ == "__main__":
    main()
