#!/usr/bin/env python3
"""
Netwatch TUI: active connection dashboard for Ubuntu/Linux.

Shows TCP/UDP sockets, process ownership, reverse DNS, optional country data,
and manual AbuseIPDB checks for selected public remote IPs.
"""

from __future__ import annotations

import curses
import hashlib
import ipaddress
import json
import getpass
import os
import queue
import re
import shutil
import socket
import stat
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


APP_NAME = "Netwatch TUI"
VERSION = "0.1.0"
CONFIG_DIR = Path.home() / ".config" / "netwatch-tui"
CONFIG_FILE = CONFIG_DIR / "config.json"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
IP_API_URL = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,message"
REFRESH_SECONDS = 3.0
EPHEMERAL_START = 32768
LOG_FILE = Path(__file__).resolve().with_name("abuseipdb_lookups.jsonl")
CAPTURE_DIR = Path(__file__).resolve().with_name("captures")
MAX_LOG_ROWS = 500


@dataclass
class Config:
    abuseipdb_key: str = ""
    remote_geo_enabled: bool = False


@dataclass
class Connection:
    proto: str
    state: str
    local_ip: str
    local_port: str
    remote_ip: str
    remote_port: str
    process: str
    pid: str
    direction: str
    hostname: str = "..."
    country: str = "..."
    abuse: str = ""
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    @property
    def key(self) -> Tuple[str, str, str, str, str, str, str]:
        return (
            self.proto,
            self.local_ip,
            self.local_port,
            self.remote_ip,
            self.remote_port,
            self.process,
            self.pid,
        )


class SafeCache:
    def __init__(self) -> None:
        self._hostnames: Dict[str, str] = {}
        self._countries: Dict[str, str] = {}
        self._lock = threading.Lock()

    def clear(self) -> None:
        with self._lock:
            self._hostnames.clear()
            self._countries.clear()

    def get_hostname(self, ip: str) -> Optional[str]:
        with self._lock:
            return self._hostnames.get(ip)

    def set_hostname(self, ip: str, value: str) -> None:
        with self._lock:
            self._hostnames[ip] = value

    def get_country(self, ip: str) -> Optional[str]:
        with self._lock:
            return self._countries.get(ip)

    def set_country(self, ip: str, value: str) -> None:
        with self._lock:
            self._countries[ip] = value



def utc_stamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def append_abuse_log(entry: Dict[str, object]) -> None:
    try:
        with LOG_FILE.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")
    except OSError:
        pass


def load_abuse_log(limit: int = MAX_LOG_ROWS) -> List[Dict[str, object]]:
    try:
        lines = LOG_FILE.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return []
    except OSError:
        return []
    rows: List[Dict[str, object]] = []
    for line in lines[-limit:]:
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            rows.append(item)
    return rows



def read_text_file(path: Path, limit: int = 65536) -> str:
    try:
        return path.read_bytes()[:limit].decode("utf-8", "replace")
    except OSError:
        return ""


def read_proc_link(path: Path) -> str:
    try:
        return os.readlink(path)
    except OSError:
        return ""


def sha256_file(path_text: str, max_bytes: int = 512 * 1024 * 1024) -> str:
    if not path_text:
        return ""
    path = Path(path_text)
    try:
        size = path.stat().st_size
        if size > max_bytes:
            return f"skipped: file larger than {max_bytes} bytes"
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError as exc:
        return f"unavailable: {exc}"


def parse_proc_status(text: str) -> Dict[str, str]:
    wanted = {
        "Name", "State", "Tgid", "Pid", "PPid", "TracerPid", "Uid", "Gid",
        "FDSize", "Groups", "VmPeak", "VmSize", "VmRSS", "Threads", "SigQ",
        "CapInh", "CapPrm", "CapEff", "CapBnd", "NoNewPrivs", "Seccomp",
    }
    data: Dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key in wanted:
            data[key] = value.strip()
    return data


def process_metadata(pid: str, include_hash: bool = True) -> Dict[str, object]:
    if not pid or not pid.isdigit():
        return {}
    base = Path("/proc") / pid
    exe = read_proc_link(base / "exe")
    cwd = read_proc_link(base / "cwd")
    root = read_proc_link(base / "root")
    cmdline_raw = read_text_file(base / "cmdline")
    cmdline = " ".join(part for part in cmdline_raw.split("\x00") if part)
    status = parse_proc_status(read_text_file(base / "status"))
    stat_text = read_text_file(base / "stat")
    fd_count = 0
    socket_fds: List[str] = []
    try:
        for fd in (base / "fd").iterdir():
            fd_count += 1
            target = read_proc_link(fd)
            if target.startswith("socket:"):
                socket_fds.append(f"{fd.name}->{target}")
    except OSError:
        pass
    exe_info: Dict[str, object] = {"path": exe}
    if exe:
        try:
            st = Path(exe).stat()
            exe_info.update({
                "size": st.st_size,
                "mode": oct(st.st_mode & 0o7777),
                "uid": st.st_uid,
                "gid": st.st_gid,
                "mtime": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(st.st_mtime)),
            })
        except OSError as exc:
            exe_info["stat_error"] = str(exc)
        if include_hash:
            exe_info["sha256"] = sha256_file(exe)
    return {
        "pid": pid,
        "exe": exe_info,
        "cwd": cwd,
        "root": root,
        "cmdline": cmdline,
        "status": status,
        "stat": stat_text.strip(),
        "fd_count": fd_count,
        "socket_fds": socket_fds[:200],
        "environment_note": "Environment variables are intentionally not captured because they often contain secrets.",
    }


def connection_to_dict(conn: Connection, include_process: bool = False) -> Dict[str, object]:
    data: Dict[str, object] = {
        "proto": conn.proto,
        "state": conn.state,
        "direction": conn.direction,
        "local_ip": conn.local_ip,
        "local_port": conn.local_port,
        "remote_ip": conn.remote_ip,
        "remote_port": conn.remote_port,
        "process": conn.process,
        "pid": conn.pid,
        "hostname": conn.hostname,
        "country": conn.country,
        "abuse": conn.abuse,
        "first_seen": conn.first_seen,
        "last_seen": conn.last_seen,
    }
    if include_process:
        data["process_metadata"] = process_metadata(conn.pid)
    return data

def load_config() -> Config:
    try:
        raw = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return Config()
    except (OSError, json.JSONDecodeError):
        return Config()
    return Config(
        abuseipdb_key=str(raw.get("abuseipdb_key", "")),
        remote_geo_enabled=bool(raw.get("remote_geo_enabled", False)),
    )


def save_config(config: Config) -> None:
    CONFIG_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    data = {
        "abuseipdb_key": config.abuseipdb_key,
        "remote_geo_enabled": config.remote_geo_enabled,
    }
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(CONFIG_FILE, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
        handle.write("\n")
    os.chmod(CONFIG_FILE, stat.S_IRUSR | stat.S_IWUSR)


def ensure_sudo() -> None:
    if os.geteuid() == 0:
        return
    if not shutil.which("sudo"):
        print("sudo is required to see process ownership for connections.", file=sys.stderr)
        sys.exit(1)
    print(f"{APP_NAME} needs sudo to show process/PID ownership for sockets.")
    try:
        subprocess.run(["sudo", "-v"], check=True)
    except subprocess.CalledProcessError:
        print("sudo authentication failed.", file=sys.stderr)
        sys.exit(1)


def terminal_api_setup(config: Config) -> Config:
    print("")
    print("AbuseIPDB checks are manual lookups only; Netwatch does not report IPs.")
    if config.abuseipdb_key:
        print("AbuseIPDB key: saved")
        choice = input("Use saved key, change it, or skip this session? [u/c/s] ").strip().lower() or "u"
        if choice.startswith("c"):
            key = getpass.getpass("New AbuseIPDB API key (blank clears saved key): ").strip()
            config.abuseipdb_key = key
            save_config(config)
            print("AbuseIPDB key saved." if key else "AbuseIPDB key cleared.")
        elif choice.startswith("s"):
            config.abuseipdb_key = ""
            print("AbuseIPDB lookups skipped for this session.")
        else:
            print("Using saved AbuseIPDB key.")
    else:
        choice = input("Add AbuseIPDB API key now? [y/N] ").strip().lower()
        if choice.startswith("y"):
            key = getpass.getpass("AbuseIPDB API key: ").strip()
            if key:
                config.abuseipdb_key = key
                save_config(config)
                print("AbuseIPDB key saved.")
            else:
                print("No key entered; AbuseIPDB lookups disabled.")
        else:
            print("Skipping AbuseIPDB key. You can still view connections.")
    print("Tip: press / to search, Tab for lookup log, q to quit.")
    input("Press Enter to open the TUI...")
    return config

def command_output(args: List[str], timeout: float = 8.0) -> str:
    proc = subprocess.run(
        args,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0 and not proc.stdout:
        return proc.stderr.strip()
    return proc.stdout


def run_ss() -> str:
    args = ["ss", "-H", "-tunap"]
    if os.geteuid() != 0 and shutil.which("sudo"):
        args = ["sudo", "-n", *args]
    return command_output(args)


def parse_endpoint(endpoint: str) -> Tuple[str, str]:
    endpoint = endpoint.strip()
    endpoint = endpoint.strip('"')
    if endpoint in {"*", "*:*"}:
        return "*", "*"
    if endpoint.startswith("["):
        match = re.match(r"^\[(.*)\]:(\*|\d+)$", endpoint)
        if match:
            return match.group(1), match.group(2)
    if endpoint.count(":") > 1:
        if endpoint.endswith(":*"):
            return endpoint[:-2], "*"
        host, _, port = endpoint.rpartition(":")
        return host, port or "*"
    if ":" in endpoint:
        host, port = endpoint.rsplit(":", 1)
        return host or "*", port or "*"
    return endpoint, "*"


def parse_process(process_blob: str) -> Tuple[str, str]:
    if not process_blob or process_blob == "-":
        return "", ""
    proc_match = re.search(r'"([^"]+)"', process_blob)
    pid_match = re.search(r"pid=(\d+)", process_blob)
    proc = proc_match.group(1) if proc_match else process_blob[:42]
    pid = pid_match.group(1) if pid_match else ""
    return proc, pid


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_global


def classify_direction(state: str, local_ip: str, local_port: str, remote_ip: str, remote_port: str) -> str:
    if state.upper() == "LISTEN" or remote_ip in {"*", "0.0.0.0", "::"}:
        return "listen"
    if remote_ip in {"127.0.0.1", "::1"} or local_ip in {"127.0.0.1", "::1"}:
        return "local"
    try:
        lp = int(local_port)
        rp = int(remote_port)
    except ValueError:
        return "flow"
    if lp < EPHEMERAL_START <= rp:
        return "in"
    if rp < EPHEMERAL_START <= lp:
        return "out"
    return "flow"


def parse_ss(text: str) -> List[Connection]:
    connections: List[Connection] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("Netid"):
            continue
        parts = line.split(None, 6)
        if len(parts) < 6:
            continue
        proto, state, _recvq, _sendq, local, remote = parts[:6]
        process_blob = parts[6] if len(parts) > 6 else ""
        local_ip, local_port = parse_endpoint(local)
        remote_ip, remote_port = parse_endpoint(remote)
        process, pid = parse_process(process_blob)
        direction = classify_direction(state, local_ip, local_port, remote_ip, remote_port)
        connections.append(
            Connection(
                proto=proto.upper(),
                state=state.upper(),
                local_ip=local_ip,
                local_port=local_port,
                remote_ip=remote_ip,
                remote_port=remote_port,
                process=process,
                pid=pid,
                direction=direction,
            )
        )
    return connections


def resolve_hostname(ip: str) -> str:
    if not is_ip(ip):
        return "-"
    parsed = ipaddress.ip_address(ip)
    if parsed.is_unspecified or parsed.is_multicast:
        return "-"
    try:
        socket.setdefaulttimeout(1.5)
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.timeout, OSError):
        return "-"


def country_from_geoiplookup(ip: str) -> Optional[str]:
    if not shutil.which("geoiplookup") or not is_public_ip(ip):
        return None
    try:
        result = subprocess.run(
            ["geoiplookup", ip],
            text=True,
            capture_output=True,
            timeout=2.5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    output = result.stdout.strip()
    if not output or ":" not in output:
        return None
    country = output.split(":", 1)[1].strip()
    country = country.replace("GeoIP Country Edition:", "").strip()
    if "IP Address not found" in country:
        return None
    return country or None


def country_from_remote(ip: str) -> Optional[str]:
    if not is_public_ip(ip):
        return "-"
    url = IP_API_URL.format(ip=urllib.parse.quote(ip))
    req = urllib.request.Request(url, headers={"User-Agent": "netwatch-tui/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=3.0) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (OSError, urllib.error.URLError, json.JSONDecodeError):
        return None
    if payload.get("status") != "success":
        return None
    country = payload.get("country") or ""
    code = payload.get("countryCode") or ""
    if country and code:
        return f"{country} ({code})"
    return country or None


def enrich_worker(
    in_queue: "queue.Queue[str]",
    out_queue: "queue.Queue[Tuple[str, str, str]]",
    cache: SafeCache,
    config: Config,
    stop: threading.Event,
) -> None:
    while not stop.is_set():
        try:
            ip = in_queue.get(timeout=0.2)
        except queue.Empty:
            continue
        if not is_ip(ip):
            out_queue.put((ip, "-", "-"))
            in_queue.task_done()
            continue
        hostname = cache.get_hostname(ip)
        if hostname is None:
            hostname = resolve_hostname(ip)
            cache.set_hostname(ip, hostname)
        country = cache.get_country(ip)
        if country is None:
            country = country_from_geoiplookup(ip)
            if country is None and config.remote_geo_enabled:
                country = country_from_remote(ip)
            country = country or "-"
            cache.set_country(ip, country)
        out_queue.put((ip, hostname, country))
        in_queue.task_done()


def abuseipdb_lookup(ip: str, api_key: str) -> Tuple[bool, str]:
    if not api_key:
        return False, "No AbuseIPDB API key is configured."
    if not is_public_ip(ip):
        return False, "Only public remote IPs can be checked with AbuseIPDB."
    params = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": "90", "verbose": "true"})
    req = urllib.request.Request(
        f"{ABUSEIPDB_URL}?{params}",
        headers={
            "Accept": "application/json",
            "Key": api_key,
            "User-Agent": "netwatch-tui/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=8.0) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            detail = exc.read().decode("utf-8")
        except OSError:
            detail = str(exc)
        return False, f"AbuseIPDB HTTP {exc.code}: {detail[:300]}"
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
        return False, f"Lookup failed: {exc}"

    data = payload.get("data", {})
    score = data.get("abuseConfidenceScore", "?")
    total = data.get("totalReports", "?")
    usage = data.get("usageType") or "unknown"
    isp = data.get("isp") or "unknown ISP"
    domain = data.get("domain") or "unknown domain"
    country = data.get("countryCode") or "unknown country"
    whitelisted = data.get("isWhitelisted")
    last_reported = data.get("lastReportedAt") or "never"
    report_line = (
        f"Abuse score {score}/100 | reports {total} | {country} | {usage} | "
        f"{isp} | {domain} | whitelisted={whitelisted} | last={last_reported}"
    )
    return True, report_line


def truncate(value: str, width: int) -> str:
    if width <= 0:
        return ""
    value = value or ""
    if len(value) <= width:
        return value
    if width <= 1:
        return value[:width]
    return value[: width - 1] + "~"


def safe_addstr(win: "curses.window", y: int, x: int, text: str, attr: int = 0) -> None:
    try:
        h, w = win.getmaxyx()
        if y < 0 or y >= h or x >= w:
            return
        win.addstr(y, x, text[: max(0, w - x - 1)], attr)
    except curses.error:
        pass


class NetwatchTUI:
    def __init__(self, stdscr: "curses.window", config: Config) -> None:
        self.stdscr = stdscr
        self.config = config
        self.cache = SafeCache()
        self.enrich_in: "queue.Queue[str]" = queue.Queue()
        self.enrich_out: "queue.Queue[Tuple[str, str, str]]" = queue.Queue()
        self.stop_event = threading.Event()
        self.workers = [
            threading.Thread(
                target=enrich_worker,
                args=(self.enrich_in, self.enrich_out, self.cache, self.config, self.stop_event),
                daemon=True,
            )
            for _ in range(8)
        ]
        self.connections: List[Connection] = []
        self.by_key: Dict[Tuple[str, str, str, str, str, str, str], Connection] = {}
        self.selected = 0
        self.scroll = 0
        self.filter_text = ""
        self.search_active = False
        self.focus_col = 4
        self.table_top = 4
        self.table_visible_h = 0
        self.column_bounds: List[Tuple[int, int, str]] = []
        self.paused = False
        self.status = "Ready"
        self.last_refresh = 0.0
        self.sort_mode = "risk"
        self.sort_reverse = False
        self.abuse_by_ip: Dict[str, str] = {}
        self.lookup_thread: Optional[threading.Thread] = None
        self.pending_ips: set[str] = set()
        self.view = "connections"
        self.help_return_view = "connections"
        self.detail_conn: Optional[Connection] = None
        self.detail_lines: List[str] = []
        self.detail_scroll = 0
        self.log_scroll = 0
        self.log_lock = threading.Lock()
        self.abuse_log: List[Dict[str, object]] = load_abuse_log()
        self.last_raw_ss = ""

    def setup(self) -> None:
        curses.curs_set(0)
        self.stdscr.nodelay(True)
        self.stdscr.keypad(True)
        try:
            curses.mousemask(curses.ALL_MOUSE_EVENTS | curses.REPORT_MOUSE_POSITION)
            curses.mouseinterval(0)
        except curses.error:
            pass
        if curses.has_colors():
            curses.start_color()
            curses.use_default_colors()
            curses.init_pair(1, curses.COLOR_CYAN, -1)
            curses.init_pair(2, curses.COLOR_GREEN, -1)
            curses.init_pair(3, curses.COLOR_YELLOW, -1)
            curses.init_pair(4, curses.COLOR_RED, -1)
            curses.init_pair(5, curses.COLOR_MAGENTA, -1)
            curses.init_pair(6, curses.COLOR_WHITE, curses.COLOR_BLUE)
            curses.init_pair(7, curses.COLOR_BLACK, curses.COLOR_CYAN)
            curses.init_pair(8, curses.COLOR_BLUE, -1)
        for worker in self.workers:
            worker.start()

    def color(self, pair: int, extra: int = 0) -> int:
        if curses.has_colors():
            return curses.color_pair(pair) | extra
        return extra

    def run(self) -> None:
        self.setup()
        if self.config.abuseipdb_key:
            self.status = "Saved AbuseIPDB key loaded. Press K to change, a to check selected IP."
        else:
            self.status = "No AbuseIPDB key yet. Press K to add one, a will prompt when needed."
        try:
            while True:
                now = time.time()
                if not self.paused and now - self.last_refresh >= REFRESH_SECONDS:
                    self.refresh()
                self.drain_enrichment()
                self.draw()
                key = self.stdscr.getch()
                if key != -1 and not self.handle_key(key):
                    break
                time.sleep(0.05)
        finally:
            self.stop_event.set()

    def refresh(self) -> None:
        raw = run_ss()
        self.last_raw_ss = raw
        parsed = parse_ss(raw)
        now = time.time()
        old = self.by_key
        new: Dict[Tuple[str, str, str, str, str, str, str], Connection] = {}
        for conn in parsed:
            previous = old.get(conn.key)
            if previous:
                conn.first_seen = previous.first_seen
                conn.hostname = previous.hostname
                conn.country = previous.country
                conn.abuse = previous.abuse
            conn.last_seen = now
            if conn.remote_ip in self.abuse_by_ip:
                conn.abuse = self.abuse_by_ip[conn.remote_ip]
            new[conn.key] = conn
            self.queue_enrich(conn.remote_ip)
        self.by_key = new
        self.connections = self.sorted_connections(list(new.values()))
        self.selected = min(self.selected, max(0, len(self.connections) - 1))
        self.last_refresh = now
        self.status = f"Refreshed {len(self.connections)} sockets"


    def capture_snapshot(self) -> None:
        rows = list(self.by_key.values())
        raw = self.last_raw_ss
        if not raw:
            raw = run_ss()
            self.last_raw_ss = raw
            rows = parse_ss(raw)

        stamp = utc_stamp()
        file_stamp = stamp.replace(":", "").replace("-", "")
        pid_metadata = {
            pid: process_metadata(pid)
            for pid in sorted({conn.pid for conn in rows if conn.pid.isdigit()}, key=int)
        }
        payload = {
            "captured_at": stamp,
            "connection_count": len(rows),
            "filter": self.filter_text,
            "sort_mode": self.sort_mode,
            "sort_reverse": self.sort_reverse,
            "connections": [connection_to_dict(conn) for conn in rows],
            "processes": pid_metadata,
            "raw_ss": raw,
            "environment_note": "Environment variables are intentionally not captured because they often contain secrets.",
        }
        text_lines = [
            f"{APP_NAME} capture",
            f"Captured at: {stamp}",
            f"Connections: {len(rows)}",
            f"Filter: {self.filter_text or '<none>'}",
            "",
            "Connections",
        ]
        for conn in sorted(rows, key=lambda item: (item.direction, item.remote_ip, item.remote_port, item.process, item.pid)):
            process = f"{conn.process}/{conn.pid}" if conn.pid else (conn.process or "-")
            text_lines.append(
                f"{conn.direction.upper():6} {conn.proto:4} {conn.state:11} "
                f"{conn.local_ip}:{conn.local_port} -> {conn.remote_ip}:{conn.remote_port} "
                f"{process} host={conn.hostname} country={conn.country} abuse={conn.abuse or '-'}"
            )
        text_lines.extend(["", "Process metadata"])
        for pid, meta in pid_metadata.items():
            exe = meta.get("exe", {}) if isinstance(meta.get("exe"), dict) else {}
            text_lines.extend([
                f"PID {pid}",
                f"  exe: {exe.get('path', '-')}",
                f"  sha256: {exe.get('sha256', '-')}",
                f"  cwd: {meta.get('cwd', '-')}",
                f"  cmdline: {meta.get('cmdline', '-')}",
                f"  socket_fds: {len(meta.get('socket_fds', []))}",
            ])
        text_lines.extend(["", "Raw ss output", raw])

        try:
            CAPTURE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
            json_path = CAPTURE_DIR / f"netwatch-{file_stamp}.json"
            text_path = CAPTURE_DIR / f"netwatch-{file_stamp}.txt"
            json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            text_path.write_text("\n".join(text_lines).rstrip() + "\n", encoding="utf-8")
        except OSError as exc:
            self.status = f"Capture failed: {exc}"
            return
        self.status = f"Captured {len(rows)} sockets to {json_path.name} and {text_path.name}"

    def sorted_connections(self, rows: List[Connection]) -> List[Connection]:
        if self.filter_text:
            rows = [row for row in rows if self.matches_filter(row, self.filter_text)]
        key_map = {
            "dir": lambda r: (r.direction, r.remote_ip, r.process.lower()),
            "proto": lambda r: (r.proto, r.remote_ip, r.process.lower()),
            "state": lambda r: (r.state, r.remote_ip, r.process.lower()),
            "local": lambda r: (r.local_ip, r.local_port, r.process.lower()),
            "remote": lambda r: (r.remote_ip, r.remote_port, r.process.lower()),
            "host": lambda r: (r.hostname, r.remote_ip, r.process.lower()),
            "country": lambda r: (r.country, r.remote_ip, r.process.lower()),
            "proc": lambda r: (r.process.lower(), r.pid, r.remote_ip),
            "ip": lambda r: (r.remote_ip, r.remote_port, r.local_ip),
        }
        key_func = self.risk_sort_key if self.sort_mode == "risk" else key_map.get(self.sort_mode, self.risk_sort_key)
        return sorted(rows, key=key_func, reverse=self.sort_reverse)

    def matches_filter(self, row: Connection, raw: str) -> bool:
        needle = raw.strip().lower()
        if not needle:
            return True
        if needle.startswith("port:"):
            port = needle.split(":", 1)[1].strip()
            return bool(port) and port in {row.local_port, row.remote_port}
        if needle.startswith(":") and needle[1:].isdigit():
            port = needle[1:]
            return port in {row.local_port, row.remote_port}
        if needle.startswith("lport:"):
            port = needle.split(":", 1)[1].strip()
            return bool(port) and row.local_port == port
        if needle.startswith("rport:"):
            port = needle.split(":", 1)[1].strip()
            return bool(port) and row.remote_port == port
        return needle in " ".join(
            [
                row.proto,
                row.state,
                row.local_ip,
                row.local_port,
                row.remote_ip,
                row.remote_port,
                f"local:{row.local_port}",
                f"remote:{row.remote_port}",
                f"lport:{row.local_port}",
                f"rport:{row.remote_port}",
                f"port:{row.local_port}",
                f"port:{row.remote_port}",
                row.hostname,
                row.country,
                row.process,
                row.pid,
                row.direction,
                row.abuse,
            ]
        ).lower()

    def risk_sort_key(self, row: Connection) -> Tuple[int, str, str]:
        score = 0
        if row.direction == "in":
            score -= 30
        if is_public_ip(row.remote_ip):
            score -= 20
        if row.abuse:
            match = re.search(r"Abuse score (\d+)", row.abuse)
            if match:
                score -= int(match.group(1))
        if row.state == "ESTAB":
            score -= 5
        return score, row.remote_ip, row.process.lower()

    def queue_enrich(self, ip: str) -> None:
        if not is_ip(ip):
            return
        if ip in self.pending_ips:
            return
        if self.cache.get_hostname(ip) is not None and self.cache.get_country(ip) is not None:
            return
        self.pending_ips.add(ip)
        try:
            self.enrich_in.put_nowait(ip)
        except queue.Full:
            self.pending_ips.discard(ip)

    def drain_enrichment(self) -> None:
        changed = False
        while True:
            try:
                ip, hostname, country = self.enrich_out.get_nowait()
            except queue.Empty:
                break
            self.pending_ips.discard(ip)
            for conn in self.by_key.values():
                if conn.remote_ip == ip:
                    conn.hostname = hostname
                    conn.country = country
                    changed = True
            self.enrich_out.task_done()
        if changed:
            self.connections = self.sorted_connections(list(self.by_key.values()))

    def draw(self) -> None:
        self.stdscr.erase()
        h, w = self.stdscr.getmaxyx()
        if h < 18 or w < 80:
            safe_addstr(self.stdscr, 0, 0, "Terminal too small. Use at least 80x18.", self.color(4, curses.A_BOLD))
            self.stdscr.refresh()
            return
        self.draw_header(h, w)
        if self.view == "abuse_log":
            self.draw_abuse_log(h, w)
        elif self.view == "connection_detail":
            self.draw_connection_detail(h, w)
        elif self.view == "help":
            self.draw_help(h, w)
        else:
            self.draw_table(h, w)
            self.draw_detail(h, w)
        self.draw_footer(h, w)
        self.stdscr.refresh()

    def draw_header(self, _h: int, w: int) -> None:
        safe_addstr(self.stdscr, 0, 0, " " * (w - 1), self.color(6, curses.A_BOLD))
        title = "[ NETWATCH TUI ]"
        safe_addstr(self.stdscr, 0, 2, title, self.color(6, curses.A_BOLD))
        active_view = "help" if self.view == "help" else ("detail" if self.view == "connection_detail" else ("log" if self.view == "abuse_log" else "connections"))
        right = f"{active_view}  {len(self.connections)} sockets  sort:{self.sort_mode}  {'paused' if self.paused else 'live'}"
        safe_addstr(self.stdscr, 0, max(0, w - len(right) - 3), right, self.color(6))
        pulse = "#*=-"
        for i, ch in enumerate(pulse * max(1, (w // len(pulse)))):
            if i >= w - 1:
                break
            if i % 11 == int(time.time() * 4) % 11:
                safe_addstr(self.stdscr, 1, i, ch, self.color(1))
            else:
                safe_addstr(self.stdscr, 1, i, "-", self.color(8))
        filter_label = f" filter: {self.filter_text or '<none>'} "
        safe_addstr(self.stdscr, 2, 2, filter_label, self.color(3))
        privacy = " DNS local | AbuseIPDB manual | remote country " + (
            "on" if self.config.remote_geo_enabled else "off"
        )
        safe_addstr(self.stdscr, 2, max(2, w - len(privacy) - 3), privacy, self.color(2))

    def draw_table(self, h: int, w: int) -> None:
        top = 4
        self.table_top = top
        detail_h = 8
        bottom = h - detail_h - 2
        cols = self.columns(w)
        labels = ["DIR", "PROTO", "STATE", "LOCAL", "REMOTE", "HOSTNAME", "COUNTRY", "PROC"]
        sort_keys = ["dir", "proto", "state", "local", "remote", "host", "country", "proc"]
        self.column_bounds = []
        safe_addstr(self.stdscr, top, 0, " " * (w - 1), self.color(7, curses.A_BOLD))
        x = 1
        for idx, (width, label, sort_key) in enumerate(zip(cols, labels, sort_keys)):
            marker = "v" if self.sort_reverse else "^"
            text = label + (marker if self.sort_mode == sort_key else "")
            attr = self.color(7, curses.A_BOLD)
            if idx == self.focus_col:
                attr |= curses.A_REVERSE
            safe_addstr(self.stdscr, top, x, truncate(text, width).ljust(width), attr)
            self.column_bounds.append((x, x + width - 1, sort_key))
            x += width + 1
        visible_h = max(1, bottom - top - 1)
        self.table_visible_h = visible_h
        if self.selected < self.scroll:
            self.scroll = self.selected
        if self.selected >= self.scroll + visible_h:
            self.scroll = self.selected - visible_h + 1
        rows = self.connections[self.scroll : self.scroll + visible_h]
        for idx, conn in enumerate(rows):
            absolute = self.scroll + idx
            y = top + 1 + idx
            attrs = self.row_attr(conn)
            if absolute == self.selected:
                attrs |= curses.A_REVERSE
            line = self.format_row(
                cols,
                [
                    conn.direction.upper(),
                    conn.proto,
                    conn.state,
                    f"{conn.local_ip}:{conn.local_port}",
                    f"{conn.remote_ip}:{conn.remote_port}",
                    conn.hostname,
                    conn.country,
                    f"{conn.process or '-'}{('/' + conn.pid) if conn.pid else ''}",
                ],
            )
            safe_addstr(self.stdscr, y, 0, " " * (w - 1), attrs)
            safe_addstr(self.stdscr, y, 1, line, attrs)
        if not rows:
            safe_addstr(self.stdscr, top + 3, 4, "No connections match the current search.", self.color(3))

    def sort_by(self, mode: str) -> None:
        if self.sort_mode == mode:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_mode = mode
            self.sort_reverse = False
        self.connections = self.sorted_connections(list(self.by_key.values()))
        self.selected = min(self.selected, max(0, len(self.connections) - 1))
        order = "desc" if self.sort_reverse else "asc"
        self.status = f"Sorted by {self.sort_mode} ({order})"

    def columns(self, width: int) -> List[int]:
        fixed = [5, 6, 11, 24, 24, 18, 18]
        remaining = max(12, width - sum(fixed) - len(fixed) - 4)
        if width < 120:
            fixed = [4, 5, 9, 20, 20, 14, 12]
            remaining = max(10, width - sum(fixed) - len(fixed) - 4)
        return [*fixed, remaining]

    def format_row(self, cols: List[int], values: Iterable[str]) -> str:
        parts = []
        for width, value in zip(cols, values):
            parts.append(truncate(str(value), width).ljust(width))
        return " ".join(parts)

    def row_attr(self, conn: Connection) -> int:
        if conn.direction == "in":
            return self.color(4, curses.A_BOLD)
        if conn.direction == "out":
            return self.color(2)
        if conn.direction == "listen":
            return self.color(5)
        if conn.direction == "local":
            return self.color(8)
        return self.color(1)

    def draw_detail(self, h: int, w: int) -> None:
        y = h - 9
        safe_addstr(self.stdscr, y, 0, "+" + "-" * (w - 3) + "+", self.color(1))
        for row in range(1, 7):
            safe_addstr(self.stdscr, y + row, 0, "|" + " " * (w - 3) + "|", self.color(1))
        safe_addstr(self.stdscr, y + 7, 0, "+" + "-" * (w - 3) + "+", self.color(1))
        conn = self.current()
        if not conn:
            safe_addstr(self.stdscr, y + 2, 3, "No selected connection.", self.color(3))
            return
        title = f"{conn.remote_ip}:{conn.remote_port}  <->  {conn.local_ip}:{conn.local_port}"
        safe_addstr(self.stdscr, y, 3, f" {truncate(title, w - 8)} ", self.color(1, curses.A_BOLD))
        age = int(time.time() - conn.first_seen)
        lines = [
            f"Process: {conn.process or '-'}  PID: {conn.pid or '-'}  State: {conn.state}  Direction: {conn.direction}",
            f"Hostname: {conn.hostname}  Country: {conn.country}  Seen: {age}s",
            f"AbuseIPDB: {conn.abuse or 'not checked'}",
            f"Selected IP is {'public' if is_public_ip(conn.remote_ip) else 'not public'}; lookups are explicit per selected connection.",
        ]
        for i, line in enumerate(lines):
            safe_addstr(self.stdscr, y + 2 + i, 3, truncate(line, w - 8), self.color(2 if i != 2 else 3))

    def build_detail_lines(self, conn: Connection) -> List[str]:
        meta = process_metadata(conn.pid)
        lines = [
            "Connection",
            f"  Direction: {conn.direction}",
            f"  Protocol:  {conn.proto}",
            f"  State:     {conn.state}",
            f"  Local:     {conn.local_ip}:{conn.local_port}",
            f"  Remote:    {conn.remote_ip}:{conn.remote_port}",
            f"  Hostname:  {conn.hostname}",
            f"  Country:   {conn.country}",
            f"  First seen: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(conn.first_seen))}",
            f"  Last seen:  {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(conn.last_seen))}",
            "",
            "AbuseIPDB",
            f"  {conn.abuse or 'not checked'}",
            "",
            "Process",
            f"  Name: {conn.process or '-'}",
            f"  PID:  {conn.pid or '-'}",
        ]
        if not meta:
            lines.append("  Process metadata unavailable. The process may have exited or PID was hidden.")
            return lines
        exe = meta.get("exe", {}) if isinstance(meta.get("exe"), dict) else {}
        lines.extend([
            f"  Command: {meta.get('cmdline') or '-'}",
            f"  Exe:     {exe.get('path') or '-'}",
            f"  CWD:     {meta.get('cwd') or '-'}",
            f"  Root:    {meta.get('root') or '-'}",
            f"  FD count: {meta.get('fd_count', '-')}",
        ])
        if exe:
            lines.extend([
                "",
                "Executable",
                f"  Size:   {exe.get('size', '-')}",
                f"  Mode:   {exe.get('mode', '-')}",
                f"  UID/GID: {exe.get('uid', '-')}/{exe.get('gid', '-')}",
                f"  MTime:  {exe.get('mtime', '-')}",
                f"  SHA256: {exe.get('sha256', '-')}",
            ])
        status = meta.get("status", {}) if isinstance(meta.get("status"), dict) else {}
        if status:
            lines.append("")
            lines.append("/proc status")
            for key in sorted(status):
                lines.append(f"  {key}: {status[key]}")
        sockets = meta.get("socket_fds", [])
        if sockets:
            lines.append("")
            lines.append("Socket file descriptors")
            for item in sockets[:80]:
                lines.append(f"  {item}")
            if len(sockets) > 80:
                lines.append(f"  ... {len(sockets) - 80} more")
        lines.extend([
            "",
            "Note",
            f"  {meta.get('environment_note', 'Environment variables are not captured.')}",
        ])
        return lines

    def open_connection_detail(self, conn: Connection) -> None:
        self.detail_conn = conn
        self.detail_lines = self.build_detail_lines(conn)
        self.detail_scroll = 0
        self.view = "connection_detail"
        self.status = f"Detail view: {conn.remote_ip}:{conn.remote_port}"

    def draw_connection_detail(self, h: int, w: int) -> None:
        top = 4
        bottom = h - 3
        visible_h = max(1, bottom - top - 1)
        max_scroll = max(0, len(self.detail_lines) - visible_h)
        self.detail_scroll = max(0, min(self.detail_scroll, max_scroll))
        safe_addstr(self.stdscr, top, 0, " " * (w - 1), self.color(7, curses.A_BOLD))
        title = "CONNECTION DETAIL"
        if self.detail_conn:
            title += f"  {self.detail_conn.remote_ip}:{self.detail_conn.remote_port}"
        safe_addstr(self.stdscr, top, 1, truncate(title, w - 2), self.color(7, curses.A_BOLD))
        shown = self.detail_lines[self.detail_scroll : self.detail_scroll + visible_h]
        for idx, line in enumerate(shown):
            y = top + 1 + idx
            attr = self.color(1, curses.A_BOLD) if line and not line.startswith(" ") else self.color(2)
            safe_addstr(self.stdscr, y, 0, " " * (w - 1), attr)
            safe_addstr(self.stdscr, y, 1, truncate(line, w - 2), attr)
        footer = f"lines {len(self.detail_lines)}  scroll {self.detail_scroll}/{max_scroll}"
        safe_addstr(self.stdscr, bottom, 1, truncate(footer, w - 2), self.color(3))

    def draw_help(self, h: int, w: int) -> None:
        top = 4
        lines = [
            "Controls",
            "  Up/Down or j/k        Move selected connection or scroll current view",
            "  PgUp/PgDn             Move faster through rows or scrollable views",
            "  Left/Right or h/l     Move focused column in connections view",
            "  Enter                 Sort by focused column",
            "  s                     Cycle common sort modes",
            "  Mouse click header    Sort by clicked column",
            "  Mouse click row       Select connection row",
            "  o                     Open/close selected connection detail",
            "  /                     Start live search",
            "  c                     Capture snapshot, or clear search when filtered",
            "  C                     Capture current incident-response snapshot",
            "  a                     AbuseIPDB lookup for selected public remote IP",
            "  Tab                   Toggle connections and AbuseIPDB lookup log",
            "  g                     Toggle remote country fallback",
            "  p                     Pause/resume live refresh",
            "  r                     Refresh current view or reload log",
            "  K                     Show API-key restart note",
            "  Esc                   Leave search/detail/help where supported",
            "  Ctrl-U                Clear typed search text while searching",
            "  ?                     Open/close this help screen",
            "  q                     Quit",
            "",
            "Search examples",
            "  firefox   1.1.1.1   Germany   ESTAB   port:443   :443   lport:22   rport:443",
            "",
            "Detail view",
            "  Press o on a selected row. It shows process path, command line, cwd, status fields,",
            "  socket file descriptors, executable metadata, and SHA-256 where readable.",
            "",
            "Capture",
            "  Press C to write JSON and text snapshots under captures/.",
            "  Environment variables are intentionally not captured because they often contain secrets.",
        ]
        safe_addstr(self.stdscr, top, 0, " " * (w - 1), self.color(7, curses.A_BOLD))
        safe_addstr(self.stdscr, top, 1, "HELP", self.color(7, curses.A_BOLD))
        for idx, line in enumerate(lines[: max(0, h - top - 4)]):
            attr = self.color(1, curses.A_BOLD) if line and not line.startswith(" ") else self.color(2)
            safe_addstr(self.stdscr, top + 2 + idx, 1, truncate(line, w - 2), attr)

    def draw_abuse_log(self, h: int, w: int) -> None:
        top = 4
        bottom = h - 3
        visible_h = max(1, bottom - top - 1)
        with self.log_lock:
            rows = list(self.abuse_log)
        self.log_scroll = max(0, min(self.log_scroll, max(0, len(rows) - visible_h)))
        safe_addstr(self.stdscr, top, 0, " " * (w - 1), self.color(7, curses.A_BOLD))
        header = "TIME                 IP                OK   RESULT"
        safe_addstr(self.stdscr, top, 1, truncate(header, w - 2), self.color(7, curses.A_BOLD))
        if not rows:
            safe_addstr(self.stdscr, top + 3, 4, "No AbuseIPDB lookups logged yet. Select a public IP and press a.", self.color(3))
            safe_addstr(self.stdscr, top + 5, 4, f"Disk log: {LOG_FILE}", self.color(2))
            return
        shown = rows[self.log_scroll : self.log_scroll + visible_h]
        for idx, entry in enumerate(shown):
            y = top + 1 + idx
            ok = "yes" if entry.get("ok") else "no"
            line = f"{entry.get('time', '-'):20} {entry.get('ip', '-'):17} {ok:4} {entry.get('message', '-')}"
            attr = self.color(2) if entry.get("ok") else self.color(4)
            safe_addstr(self.stdscr, y, 0, " " * (w - 1), attr)
            safe_addstr(self.stdscr, y, 1, truncate(line, w - 2), attr)
        safe_addstr(self.stdscr, bottom, 1, truncate(f"Disk log: {LOG_FILE}  rows {len(rows)}", w - 2), self.color(3))

    def draw_footer(self, h: int, w: int) -> None:
        safe_addstr(self.stdscr, h - 1, 0, " " * (w - 1), self.color(6))
        if self.view == "abuse_log":
            keys = "Tab connections  Up/Down scroll  r reload  ? help  q quit"
        elif self.view == "connection_detail":
            keys = "Esc/o back  Up/Down scroll  C capture  a abuse  ? help  q quit"
        elif self.view == "help":
            keys = "Esc/? back  q quit"
        else:
            keys = "? help  o details  c/C capture  / search  a abuse  Tab log  arrows move/sort  q quit"
        safe_addstr(self.stdscr, h - 1, 1, truncate(keys, w - 2), self.color(6))
        safe_addstr(self.stdscr, h - 2, 0, " " * (w - 1), self.color(6 if self.search_active else 0))
        if self.search_active:
            search = f"Search: {self.filter_text}_   port:443 :443 lport:22 rport:443   Esc done"
            safe_addstr(self.stdscr, h - 2, 1, truncate(search, w - 2), self.color(6, curses.A_BOLD))
        else:
            safe_addstr(self.stdscr, h - 2, 1, truncate(self.status, w - 2), self.color(3))

    def current(self) -> Optional[Connection]:
        if not self.connections:
            return None
        self.selected = max(0, min(self.selected, len(self.connections) - 1))
        return self.connections[self.selected]

    def handle_key(self, key: int) -> bool:
        if self.search_active:
            return self.handle_search_key(key)
        if key in (ord("?"),):
            self.toggle_help()
            return True
        if self.view == "help":
            return self.handle_help_key(key)
        if key in (9,):
            self.toggle_view()
            return True
        if self.view == "connection_detail":
            return self.handle_detail_key(key)
        if self.view == "abuse_log":
            return self.handle_log_key(key)
        if key in (ord("q"), ord("Q")):
            return False
        if key in (curses.KEY_DOWN, ord("j")):
            self.selected = min(len(self.connections) - 1, self.selected + 1)
        elif key in (curses.KEY_UP, ord("k")):
            self.selected = max(0, self.selected - 1)
        elif key in (curses.KEY_RIGHT, ord("l")):
            self.focus_col = min(7, self.focus_col + 1)
            self.status = "Focused column: " + self.focused_column_name()
        elif key in (curses.KEY_LEFT, ord("h")):
            self.focus_col = max(0, self.focus_col - 1)
            self.status = "Focused column: " + self.focused_column_name()
        elif key in (10, 13):
            self.sort_focused_column()
        elif key in (curses.KEY_MOUSE,):
            self.handle_mouse()
        elif key in (curses.KEY_NPAGE,):
            self.selected = min(len(self.connections) - 1, self.selected + 10)
        elif key in (curses.KEY_PPAGE,):
            self.selected = max(0, self.selected - 10)
        elif key in (ord("r"), ord("R")):
            self.refresh()
        elif key in (ord("p"), ord("P")):
            self.paused = not self.paused
            self.status = "Paused" if self.paused else "Live refresh resumed"
        elif key in (ord("a"), ord("A")):
            self.lookup_selected()
        elif key in (ord("o"), ord("O")):
            conn = self.current()
            if conn:
                self.open_connection_detail(conn)
        elif key == ord("C"):
            self.capture_snapshot()
        elif key == ord("/"):
            self.search_active = True
            self.status = "Search mode"
        elif key == ord("c"):
            if self.filter_text:
                self.clear_search()
            else:
                self.capture_snapshot()
        elif key in (ord("s"), ord("S")):
            self.cycle_sort()
        elif key == ord("K"):
            self.status = "Restart the script to add/change the AbuseIPDB key before the TUI opens."
        elif key in (ord("g"), ord("G")):
            self.config.remote_geo_enabled = not self.config.remote_geo_enabled
            save_config(self.config)
            self.cache.clear()
            self.status = "Remote country fallback " + ("enabled" if self.config.remote_geo_enabled else "disabled")
            self.refresh()
        elif key == curses.KEY_RESIZE:
            pass
        return True

    def toggle_help(self) -> None:
        if self.view == "help":
            self.view = self.help_return_view
            self.status = "Help closed"
        else:
            self.help_return_view = self.view
            self.view = "help"
            self.search_active = False
            self.status = "Help"

    def handle_help_key(self, key: int) -> bool:
        if key in (ord("q"), ord("Q")):
            return False
        if key in (27, ord("?")):
            self.view = self.help_return_view
            self.status = "Help closed"
        return True

    def handle_detail_key(self, key: int) -> bool:
        if key in (ord("q"), ord("Q")):
            return False
        if key in (27, ord("o"), ord("O")):
            self.view = "connections"
            self.status = "Connections view"
        elif key in (curses.KEY_DOWN, ord("j")):
            self.detail_scroll += 1
        elif key in (curses.KEY_UP, ord("k")):
            self.detail_scroll = max(0, self.detail_scroll - 1)
        elif key in (curses.KEY_NPAGE,):
            self.detail_scroll += max(1, self.table_visible_h or 10)
        elif key in (curses.KEY_PPAGE,):
            self.detail_scroll = max(0, self.detail_scroll - max(1, self.table_visible_h or 10))
        elif key in (ord("a"), ord("A")):
            self.lookup_selected()
            if self.detail_conn:
                self.detail_lines = self.build_detail_lines(self.detail_conn)
        elif key == ord("C"):
            self.capture_snapshot()
        return True

    def toggle_view(self) -> None:
        self.search_active = False
        self.view = "abuse_log" if self.view == "connections" else "connections"
        if self.view == "abuse_log":
            with self.log_lock:
                self.abuse_log = load_abuse_log()
            self.status = f"AbuseIPDB lookup log: {LOG_FILE}"
        else:
            self.status = "Connections view"

    def handle_log_key(self, key: int) -> bool:
        if key in (ord("q"), ord("Q")):
            return False
        if key in (9,):
            self.toggle_view()
        elif key in (curses.KEY_DOWN, ord("j")):
            self.log_scroll += 1
        elif key in (curses.KEY_UP, ord("k")):
            self.log_scroll = max(0, self.log_scroll - 1)
        elif key in (curses.KEY_NPAGE,):
            self.log_scroll += max(1, self.table_visible_h or 10)
        elif key in (curses.KEY_PPAGE,):
            self.log_scroll = max(0, self.log_scroll - max(1, self.table_visible_h or 10))
        elif key in (ord("r"), ord("R")):
            with self.log_lock:
                self.abuse_log = load_abuse_log()
            self.status = "Reloaded AbuseIPDB lookup log"
        return True

    def handle_search_key(self, key: int) -> bool:
        if key in (27, 10, 13):
            self.search_active = False
            self.status = f"Search active: {self.filter_text!r}" if self.filter_text else "Search cleared"
            return True
        if key in (ord("q"),) and not self.filter_text:
            self.search_active = False
            return True
        if key in (curses.KEY_BACKSPACE, 127, 8):
            self.filter_text = self.filter_text[:-1]
            self.apply_search()
            return True
        if key == 21:
            self.filter_text = ""
            self.apply_search()
            return True
        if key == curses.KEY_MOUSE:
            self.handle_mouse()
            return True
        if 32 <= key <= 126 and len(self.filter_text) < 120:
            self.filter_text += chr(key)
            self.apply_search()
        return True

    def apply_search(self) -> None:
        self.connections = self.sorted_connections(list(self.by_key.values()))
        self.selected = min(self.selected, max(0, len(self.connections) - 1))
        self.scroll = min(self.scroll, max(0, len(self.connections) - 1))

    def clear_search(self) -> None:
        self.filter_text = ""
        self.search_active = False
        self.connections = self.sorted_connections(list(self.by_key.values()))
        self.selected = 0
        self.scroll = 0
        self.status = "Search cleared"

    def focused_column_name(self) -> str:
        names = ["dir", "proto", "state", "local", "remote", "host", "country", "proc"]
        return names[self.focus_col]

    def sort_focused_column(self) -> None:
        self.sort_by(self.focused_column_name())

    def handle_mouse(self) -> None:
        try:
            _id, x, y, _z, button = curses.getmouse()
        except curses.error:
            return
        if not (button & (curses.BUTTON1_CLICKED | curses.BUTTON1_PRESSED | curses.BUTTON1_RELEASED)):
            return
        if y == self.table_top:
            for idx, (left, right, sort_key) in enumerate(self.column_bounds):
                if left <= x <= right:
                    self.focus_col = idx
                    self.sort_by(sort_key)
                    return
        row_index = y - self.table_top - 1
        if 0 <= row_index < self.table_visible_h:
            absolute = self.scroll + row_index
            if 0 <= absolute < len(self.connections):
                self.selected = absolute
                conn = self.connections[absolute]
                self.status = f"Selected {conn.remote_ip}:{conn.remote_port}. Press o for details."

    def cycle_sort(self) -> None:
        modes = ["risk", "remote", "proc", "country", "state"]
        index = modes.index(self.sort_mode) if self.sort_mode in modes else 0
        self.sort_mode = modes[(index + 1) % len(modes)]
        self.sort_reverse = False
        self.connections = self.sorted_connections(list(self.by_key.values()))
        self.status = f"Sort mode: {self.sort_mode}"

    def lookup_selected(self) -> None:
        conn = self.current()
        if not conn:
            return
        ip = conn.remote_ip
        if self.lookup_thread and self.lookup_thread.is_alive():
            self.status = "AbuseIPDB lookup already running"
            return
        if not self.config.abuseipdb_key:
            self.status = "No AbuseIPDB key for this session. Restart and choose y/change at startup."
            return
        self.status = f"Checking {ip} with AbuseIPDB..."
        self.lookup_thread = threading.Thread(target=self.lookup_ip_thread, args=(ip,), daemon=True)
        self.lookup_thread.start()

    def lookup_ip_thread(self, ip: str) -> None:
        ok, message = abuseipdb_lookup(ip, self.config.abuseipdb_key)
        entry = {
            "time": utc_stamp(),
            "ip": ip,
            "ok": ok,
            "message": message,
        }
        append_abuse_log(entry)
        with self.log_lock:
            self.abuse_log.append(entry)
            self.abuse_log = self.abuse_log[-MAX_LOG_ROWS:]
        self.abuse_by_ip[ip] = message
        for conn in self.by_key.values():
            if conn.remote_ip == ip:
                conn.abuse = message
        self.status = message if ok else f"AbuseIPDB: {message}"


def main(stdscr: "curses.window", config: Config) -> None:
    app = NetwatchTUI(stdscr, config)
    app.run()


if __name__ == "__main__":
    ensure_sudo()
    if not shutil.which("ss"):
        print("ss is required. Install iproute2 on Ubuntu: sudo apt install iproute2", file=sys.stderr)
        sys.exit(1)
    try:
        config = terminal_api_setup(load_config())
        curses.wrapper(lambda stdscr: main(stdscr, config))
    except KeyboardInterrupt:
        pass
