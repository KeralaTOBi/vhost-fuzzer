#!/usr/bin/env python3
"""
vhost_fuzz.py — Full-port probe + VHost fuzzing with ffuf

Flow:
  1. For each resolved host → TCP connect scan all 65535 ports (parallel)
  2. Filter to only HTTP-responding ports (banner grab / HTTP probe)
  3. For each confirmed HTTP port → run ffuf with wordlist as Host header
  4. Filter/match by status code, title, content-length, word count
  5. Collect hits → results/<host>_<port>.json + summary.txt

Usage:
    python3 vhost_fuzz.py -r resolved.txt -w subdomains.txt [options]
"""

import argparse
import subprocess
import sys
import json
import time
import socket
import logging
import urllib.request
import urllib.error
import ssl
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("vhost_fuzz")

ALL_PORTS = range(1, 65536)

# ─────────────────────────────────────────────────────────────────────────────
# Port scanner
# ─────────────────────────────────────────────────────────────────────────────
def tcp_connect(host: str, port: int, timeout: float) -> int | None:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return port
    except Exception:
        return None


def scan_ports_raw(host: str, timeout: float, max_workers: int) -> list[int]:
    """Pure TCP connect scan — may include false positives on CDN/cloud IPs."""
    open_ports = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(tcp_connect, host, p, timeout): p for p in ALL_PORTS}
        for fut in as_completed(futures):
            r = fut.result()
            if r is not None:
                open_ports.append(r)
    return sorted(open_ports)


# ─────────────────────────────────────────────────────────────────────────────
# HTTP validation — confirm a port actually speaks HTTP/HTTPS
# ─────────────────────────────────────────────────────────────────────────────
def http_probe(host: str, port: int, timeout: float) -> str | None:
    """
    Try HTTP then HTTPS on the port.
    Returns 'http', 'https', or None if neither responds with an HTTP reply.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE

    for scheme in ("https", "http"):
        url = f"{scheme}://{host}:{port}/"
        try:
            req = urllib.request.Request(
                url,
                headers={"Host": host, "User-Agent": "Mozilla/5.0"},
            )
            if scheme == "https":
                resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
            else:
                resp = urllib.request.urlopen(req, timeout=timeout)
            resp.read(64)   # consume a bit so the connection is valid
            return scheme
        except urllib.error.HTTPError:
            # Got an HTTP error code → still speaks HTTP
            return scheme
        except Exception:
            continue
    return None


def filter_http_ports(
    host: str, ports: list[int], timeout: float, max_workers: int
) -> list[tuple[int, str]]:
    """
    From a list of open TCP ports, return only those that respond to HTTP/HTTPS.
    Returns list of (port, scheme) tuples.
    """
    confirmed: list[tuple[int, str]] = []

    def probe(port):
        scheme = http_probe(host, port, timeout)
        return (port, scheme)

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(probe, p): p for p in ports}
        for fut in as_completed(futures):
            port, scheme = fut.result()
            if scheme:
                confirmed.append((port, scheme))

    return sorted(confirmed, key=lambda x: x[0])


def scan_ports(host: str, port_timeout: float, http_timeout: float,
               scan_workers: int, http_workers: int) -> list[tuple[int, str]]:
    log.info(f"  🔍 TCP scan {host}:1-65535  threads={scan_workers}  timeout={port_timeout}s")
    t0 = time.time()
    raw = scan_ports_raw(host, port_timeout, scan_workers)
    log.info(f"  📡 {len(raw)} TCP-open ports in {time.time()-t0:.1f}s → HTTP probing...")

    t1 = time.time()
    http_ports = filter_http_ports(host, raw, http_timeout, http_workers)
    log.info(
        f"  ✅ {len(http_ports)} HTTP ports confirmed in {time.time()-t1:.1f}s: "
        + ", ".join(f"{p}({s})" for p, s in http_ports)
    )
    return http_ports


# ─────────────────────────────────────────────────────────────────────────────
# ffuf
# ─────────────────────────────────────────────────────────────────────────────
def check_ffuf() -> str:
    r = subprocess.run(["which", "ffuf"], capture_output=True, text=True)
    if r.returncode != 0:
        log.error("ffuf not found. Install: https://github.com/ffuf/ffuf")
        sys.exit(1)
    log.info(f"ffuf: {r.stdout.strip()}")
    return r.stdout.strip()


def sanitize(name: str) -> str:
    return name.replace("://", "_").replace("/", "_").replace(":", "_")


def build_ffuf_cmd(
    ffuf_bin: str, target: str, port: int, scheme: str,
    wordlist: str, out_json: str, args: argparse.Namespace
) -> list[str]:
    url = f"{scheme}://{target}:{port}/"
    cmd = [
        ffuf_bin,
        "-u",       url,
        "-w",       f"{wordlist}:FUZZ",
        "-H",       "Host: FUZZ",
        "-t",       str(args.fuzz_threads),
        "-timeout", str(args.request_timeout),
        "-mc",      args.mc,
        "-fc",      args.fc,
        "-o",       out_json,
        "-of",      "json",
        "-noninteractive",
        "-s",
    ]
    if args.ft: cmd += ["-ft", args.ft]
    if args.mt: cmd += ["-mt", args.mt]
    if args.fl: cmd += ["-fl", args.fl]
    if args.ml: cmd += ["-ml", args.ml]
    if args.fw: cmd += ["-fw", args.fw]
    if args.mw: cmd += ["-mw", args.mw]
    if args.rate > 0:
        cmd += ["-rate", str(args.rate)]
    if scheme == "https":
        cmd += ["-k"]
    return cmd


def run_ffuf(cmd: list[str], label: str) -> None:
    log.info(f"  ▶  ffuf → {label}")
    if log.isEnabledFor(logging.DEBUG):
        log.debug("CMD: " + " ".join(cmd))
    subprocess.run(cmd, capture_output=not log.isEnabledFor(logging.DEBUG))


def parse_hits(json_path: str) -> list[dict]:
    try:
        with open(json_path) as f:
            return json.load(f).get("results", [])
    except Exception:
        return []


def print_hit(hit: dict, port: int, scheme: str) -> None:
    vhost  = hit.get("input", {}).get("FUZZ", "?")
    status = hit.get("status",  "?")
    length = hit.get("length",  "?")
    words  = hit.get("words",   "?")
    url    = hit.get("url",     "?")
    title  = hit.get("title",   "?")   # ffuf includes title in newer builds
    log.info(
        f"    🎯 HIT  status={status}  len={length}  words={words}  "
        f"title=\"{title}\"  Host={vhost}  {scheme}:{port}  {url}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        description="Full-port VHost fuzzer (TCP scan → HTTP validate → ffuf)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    ap.add_argument("-r", "--resolved", required=True,
                    help="File with resolved hosts/IPs (one per line)")
    ap.add_argument("-w", "--wordlist", required=True,
                    help="Subdomain wordlist used as Host header")

    # Port scan
    ap.add_argument("--scan-threads", type=int,   default=1000,
                    help="Parallel TCP connect threads (default: 1000)")
    ap.add_argument("--port-timeout", type=float, default=0.5,
                    help="TCP connect timeout seconds (default: 0.5)")

    # HTTP validation
    ap.add_argument("--http-threads", type=int,   default=100,
                    help="Parallel HTTP probe threads (default: 100)")
    ap.add_argument("--http-timeout", type=float, default=5.0,
                    help="HTTP probe timeout seconds (default: 5.0)")

    # ffuf
    ap.add_argument("--fuzz-threads",    type=int, default=50)
    ap.add_argument("--request-timeout", type=int, default=10)
    ap.add_argument("--rate",            type=int, default=150,
                    help="ffuf req/sec, 0=unlimited (default: 150)")

    # Filters / matchers
    ap.add_argument("--mc", default="200,204,301,302,307,401,403,405",
                    help="Match status codes")
    ap.add_argument("--fc", default="404",
                    help="Filter status codes")
    ap.add_argument("--ft", default=None, metavar="REGEX",
                    help="Filter title regex  e.g. 'Not Found|Default Page'")
    ap.add_argument("--mt", default=None, metavar="REGEX",
                    help="Match title regex")
    ap.add_argument("--fl", default=None, metavar="SIZES",
                    help="Filter content-length (comma-separated)")
    ap.add_argument("--ml", default=None, metavar="SIZES",
                    help="Match content-length (comma-separated)")
    ap.add_argument("--fw", default=None, metavar="COUNTS",
                    help="Filter word count (comma-separated)")
    ap.add_argument("--mw", default=None, metavar="COUNTS",
                    help="Match word count (comma-separated)")

    ap.add_argument("--output",  default="vhost_results")
    ap.add_argument("--resume",  action="store_true",
                    help="Skip already-completed (host,port) pairs")
    ap.add_argument("--verbose", action="store_true")

    args = ap.parse_args()
    if args.verbose:
        log.setLevel(logging.DEBUG)

    ffuf_bin = check_ffuf()

    rp = Path(args.resolved)
    if not rp.is_file():
        log.error(f"Not found: {args.resolved}"); sys.exit(1)
    resolved = [
        l.strip().split("//")[-1].split("/")[0]
        for l in rp.read_text().splitlines() if l.strip()
    ]
    log.info(f"Resolved hosts : {len(resolved)}")

    wl = Path(args.wordlist)
    if not wl.is_file():
        log.error(f"Not found: {args.wordlist}"); sys.exit(1)
    log.info(f"Wordlist       : {args.wordlist}")

    filter_summary = f"mc={args.mc}  fc={args.fc}"
    for flag, val in [("ft",args.ft),("mt",args.mt),("fl",args.fl),
                      ("ml",args.ml),("fw",args.fw),("mw",args.mw)]:
        if val: filter_summary += f"  {flag}={val}"
    log.info(f"Filters        : {filter_summary}")

    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    scan_cache = out_dir / "open_ports.json"
    port_cache: dict[str, list[list]] = {}   # host → [[port, scheme], ...]
    if scan_cache.exists():
        try:
            port_cache = json.loads(scan_cache.read_text())
            log.info(f"Loaded port-scan cache ({len(port_cache)} hosts)")
        except Exception:
            pass

    all_hits: list[dict] = []
    start = time.time()

    for idx, host in enumerate(resolved, 1):
        print()
        log.info("=" * 64)
        log.info(f"[{idx}/{len(resolved)}]  {host}")

        # 1. Port scan + HTTP validation
        if host in port_cache:
            http_ports = [tuple(x) for x in port_cache[host]]
            log.info(f"  📋 Cached HTTP ports: " +
                     ", ".join(f"{p}({s})" for p, s in http_ports))
        else:
            http_ports = scan_ports(
                host,
                args.port_timeout, args.http_timeout,
                args.scan_threads, args.http_threads,
            )
            port_cache[host] = [list(x) for x in http_ports]
            scan_cache.write_text(json.dumps(port_cache, indent=2))

        if not http_ports:
            log.info("  ⚠️  No HTTP ports found — skipping")
            continue

        # 2. VHost fuzz each confirmed HTTP port
        for port, scheme in http_ports:
            out_json = str(out_dir / f"{sanitize(host)}_{port}.json")
            label    = f"{scheme}://{host}:{port}"

            if args.resume and Path(out_json).exists():
                log.info(f"  ⏭  SKIP (resume): {label}")
                all_hits.extend(parse_hits(out_json))
                continue

            cmd = build_ffuf_cmd(ffuf_bin, host, port, scheme, str(wl), out_json, args)
            run_ffuf(cmd, label)

            hits = parse_hits(out_json)
            for h in hits:
                print_hit(h, port, scheme)
            all_hits.extend(hits)

    # Summary
    elapsed = time.time() - start
    print()
    log.info("=" * 64)
    log.info(f"Done in {elapsed:.0f}s — {len(all_hits)} total hits")

    if all_hits:
        summary = out_dir / "summary.txt"
        with open(summary, "w") as f:
            f.write(f"# VHost Fuzz Summary — {datetime.now().isoformat()}\n")
            f.write("# status\tlength\twords\ttitle\tHost\tURL\n\n")
            for h in all_hits:
                vhost = h.get("input", {}).get("FUZZ", "?")
                f.write(
                    f"{h.get('status','?')}\t{h.get('length','?')}\t"
                    f"{h.get('words','?')}\t{h.get('title','?')}\t"
                    f"{vhost}\t{h.get('url','?')}\n"
                )
        log.info(f"Summary → {summary}")

    log.info(f"Port cache → {scan_cache}")


if __name__ == "__main__":
    main()
