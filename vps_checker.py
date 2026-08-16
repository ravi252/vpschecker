#!/usr/bin/env python3
"""
VPS Checker
===========

Reads a text file full of VPS servers (ip / port / user / pass) and checks
each one over SSH to find out which are still working and which have died.
That way you can quickly delete the VPSes that stopped working.

What "working" means
--------------------
A server is considered WORKING only if:
  1. its SSH port is reachable (TCP connect), AND
  2. we can successfully log in with the given user/password.

A server is reported as:
  * OK            - alive and login works  (keep it)
  * UNREACHABLE   - port closed / timeout  (probably DEAD -> delete it)
  * AUTH_FAILED   - up, but the credentials did not log in

Every WORKING box also gets its specs pulled (OS / CPU / RAM / disk / uptime)
and written to working.txt, so you can tell the boxes apart, e.g.
"Ubuntu 24.04.4 LTS | 4 vCPU | 7.5 GiB RAM | 30 GiB disk | up 3d 2h".

Usage
-----
    python vps_checker.py                          # uses ./vps_list.txt
    python vps_checker.py my_vps.txt               # specify the list file
    python vps_checker.py my_vps.txt --timeout 8 --workers 16
    python vps_checker.py --ping-only              # only check TCP reachability
    python vps_checker.py --json                   # machine-readable output

Automation / not-forgetting-to-delete
-------------------------------------
Every run records health history so a server is only "confirmed dead" after
several checks in a row (default: 3). That history survives across runs:

    --state FILE          health-history file  (default: vps_state.json)
    --log FILE            append-only audit log (default: vps_checker.log)
    --export-delete FILE  write the confirmed-dead list (default: to_delete.txt)
    --export-working FILE write the WORKING servers + their specs (default: working.txt)
    --no-info             skip gathering specs (OS / RAM / disk) of working boxes
    --threshold N         consecutive DEAD checks before "safe to delete" (3)
    --loop                keep checking forever
    --interval DURATION   how often in --loop mode: 30s / 5m / 6h / 1d (default 1d)
    --install-task        register a Windows Scheduled Task (daily, hands-off)
    --remove-task         delete that Scheduled Task again
    --task-time HH:MM     daily start time for the task (default: 08:00)

So a typical setup is: put your servers in vps_list.txt, then run
    python vps_checker.py --install-task
and it re-checks daily, builds up the "dead for N days" history, and writes a
ready-to-delete list to to_delete.txt so you never have to guess which to kill.

List file format (one server per line, '#' = comment, blank lines ignored):
    192.0.2.10:22:root:hunter2          # ip:port:user:password
    192.0.2.10:22 root hunter2          # space form (port after ip)
    192.0.2.11 admin "secret pass"      # port defaults to 22
    198.51.100.5,2222,ubuntu,mypass     # comma form also works
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from typing import List, Optional, Tuple

try:
    import paramiko
except ImportError:  # pragma: no cover
    paramiko = None  # allow --ping-only without the SSH dependency
else:
    import logging
    logging.getLogger("paramiko").setLevel(logging.CRITICAL)


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class Vps:
    """A single VPS target read from the list file."""

    ip: str
    port: int
    user: str
    password: str
    line: int  # line number in the file (for error reporting)

    @property
    def label(self) -> str:
        return f"{self.ip}:{self.port}"


@dataclass
class Result:
    """Outcome of checking one VPS."""

    ip: str
    port: int
    user: str
    status: str  # "OK" | "UNREACHABLE" | "AUTH_FAILED" | "ERROR" | "SKIPPED"
    detail: str = ""
    latency_ms: Optional[int] = None
    os: Optional[str] = None
    hostname: Optional[str] = None
    cpu: Optional[str] = None
    ram: Optional[str] = None
    disk: Optional[str] = None
    swap: Optional[str] = None
    uptime: Optional[str] = None
    password: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.status == "OK"

    @property
    def label(self) -> str:
        """Human-friendly 'ip:port' identifier used in the report."""
        return f"{self.ip}:{self.port}"


# --------------------------------------------------------------------------- #
# Parsing the list file
# --------------------------------------------------------------------------- #
def _split_hostport(hostport: str, default_port: int = 22) -> Tuple[str, int]:
    """Split an 'ip' or 'ip:port' string into (ip, port)."""
    hostport = hostport.strip()
    if hostport.count(":") == 1:
        host, _, port = hostport.rpartition(":")
        try:
            return host, int(port)
        except ValueError:
            return host, default_port
    return hostport, default_port


def _unquote(value: str) -> str:
    """Remove one pair of matching surrounding quotes, if present."""
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1].strip()
    return value


def parse_line(raw: str) -> Optional[Vps]:
    """Parse one list line into a Vps (or None to skip it).

    Uses the same robust extractor as extract_vps.py (URLs, user@ip:pass,
    leading text and ip:port:user:pass all work), then falls back to the
    simple space/CSV forms for anything extract_one does not recognise.
    """
    line = raw.strip()
    if not line or line.startswith("#") or line.startswith(";"):
        return None
    try:
        import extract_vps
        clean = extract_vps.extract_one(line)
    except Exception:
        clean = None
    if clean:
        parts = clean.split(":", 3)
        if len(parts) == 4 and parts[0].strip() and parts[2].strip():
            ip, port, user, password = parts
            try:
                port_int = int(port.strip())
            except ValueError:
                port_int = 22
            return Vps(ip=ip.strip(), port=port_int,
                       user=user.strip(), password=password, line=0)
    if _has_real_ipv4(line):
        return _parse_legacy(raw)
    return None


def _has_real_ipv4(line: str) -> bool:
    """True only if the line contains a real IPv4 (every octet 0-255)."""
    import re
    m = re.search(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])", line)
    if not m:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in m.group(1).split("."))


def _parse_legacy(raw: str) -> Optional[Vps]:
    """Parse a single line into a Vps, or None if it should be skipped.

    Accepted forms:
      * Colon:            ip:port:user:password         (or ip:user:password)
      * CSV (4 fields):   ip , port , user , password
      * CSV (3 fields):   ip , user , password          (port defaults to 22)
      * Space:            ip[:port] user password...    (rest of line = password)
    """
    line = raw.strip()
    if not line or line.startswith("#") or line.startswith(";"):
        return None

    # --- comma / CSV form --------------------------------------------------- #
    if "," in line:
        parts = [p.strip() for p in line.split(",")]
        # drop any trailing empties from a stray comma, keep at least 3
        while len(parts) > 3 and parts[-1] == "":
            parts = parts[:-1]
        if len(parts) == 3:
            first, user, password = parts
            ip, port = _split_hostport(first)
            return Vps(ip=ip, port=port, user=_unquote(user),
                       password=_unquote(password), line=0)
        if len(parts) >= 4:
            ip = parts[0].strip()
            port = int(parts[1]) if parts[1].strip().isdigit() else 22
            user = _unquote(parts[2])
            # password may itself contain commas -> rejoin the tail
            password = _unquote(",".join(parts[3:]))
            return Vps(ip=ip, port=port, user=user, password=password, line=0)
        return None

    # --- colon separated form: ip[:port]:user:password --------------------- #
    # A space-separated line never has more than one colon in its first token
    # (just 'ip' or 'ip:port'), so two or more there means ip:...:user:pass.
    first_token = line.split(None, 1)[0]
    if first_token.count(":") >= 2:
        parts = line.split(":")
        ip = parts[0].strip()
        if parts[1].strip().isdigit() and len(parts) >= 4:
            # ip : port : user : password
            port = int(parts[1])
            user = _unquote(parts[2])
            # password may itself contain ':' -> rejoin the tail
            password = _unquote(":".join(parts[3:]))
            return Vps(ip=ip, port=port, user=user, password=password, line=0)
        if not parts[1].strip().isdigit():
            # ip : user : password   (no explicit port -> 22)
            user = _unquote(parts[1])
            password = _unquote(":".join(parts[2:]))
            return Vps(ip=ip, port=22, user=user, password=password, line=0)
        # 'ip:port:??? ' with no user is ambiguous -> fall through below

    # --- space separated form ---------------------------------------------- #
    tokens = line.split()
    if len(tokens) >= 2:
        hostport = tokens[0]
        user = _unquote(tokens[1])
        password = _unquote(" ".join(tokens[2:]))  # keep spaces in password
        ip, port = _split_hostport(hostport)
        return Vps(ip=ip, port=port, user=user, password=password, line=0)

    return None


def load_vps(path: str) -> List[Vps]:
    """Read and parse the whole list file."""
    if not os.path.isfile(path):
        raise FileNotFoundError(
            f"VPS list file not found: {path}\n"
            f"Create it first (see vps_list.txt for an example) or pass a "
            f"different file."
        )

    vps: List[Vps] = []
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, start=1):
            v = parse_line(raw)
            if v is None:
                continue
            v.line = lineno
            vps.append(v)
    return vps


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #
def _tcp_reachable(ip: str, port: int, timeout: float) -> Tuple[bool, str]:
    """Cheap TCP connect test. Returns (reachable, reason)."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True, ""
    except socket.timeout:
        return False, "connection timed out"
    except ConnectionRefusedError:
        return False, "connection refused"
    except socket.gaierror as exc:
        return False, f"DNS error: {exc}"
    except OSError as exc:
        return False, f"network error: {exc}"


def _human_uptime(seconds: Optional[int]) -> Optional[str]:
    """Turn a raw uptime in seconds into e.g. '3d 2h' / '5m' / '42s'."""
    if seconds is None or seconds < 0:
        return None
    days, rem = divmod(int(seconds), 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m"
    return f"{int(seconds)}s"


def _get_system_info(client, max_seconds: float = 10) -> dict:
    """Once logged in, pull the box's specs (OS / CPU / RAM / disk / swap /
    uptime) so you can tell the surviving boxes apart.

    Everything is fetched with a SINGLE ssh exec_command (one round-trip).
    The remote shell prints KEY=VALUE lines; if a given tool is missing on a
    weird distro, that field simply comes back as None -- the box is still OK.

    The read is hard-bounded by ``max_seconds`` of wall-clock time, so a
    remote shell that never closes the channel can't hang the checker.
    """
    info = {
        "hostname": None,
        "os": None,
        "cpu": None,
        "ram": None,
        "disk": None,
        "swap": None,
        "uptime": None,
    }
    cmd = (
        'echo "HOSTNAME=$(hostname 2>/dev/null)"; '
        'echo "OS=$(grep -E "^PRETTY_NAME=" /etc/os-release 2>/dev/null'
        ' | cut -d= -f2-)"; '
        'echo "CPU=$(nproc 2>/dev/null)"; '
        "echo \"MEM_MB=$(free -m 2>/dev/null | awk '/^Mem:/{print $2}')\"; "
        "echo \"SWAP_MB=$(free -m 2>/dev/null | awk '/^Swap:/{print $2}')\"; "
        "echo \"DISK_MB=$(df -m / 2>/dev/null | awk 'NR==2{print $2}')\"; "
        'echo "UPTIME_S=$(cut -d. -f1 /proc/uptime 2>/dev/null)"'
    )
    deadline = time.monotonic() + max_seconds
    try:
        _stdin, stdout, _stderr = client.exec_command(cmd, timeout=max_seconds)
    except Exception:
        return info
    try:
        stdout.channel.settimeout(max_seconds)
    except Exception:
        pass
    out = b""
    while time.monotonic() < deadline:
        try:
            chunk = stdout.channel.recv(65536)
        except (socket.timeout, EOFError):
            break
        except Exception:
            break
        if not chunk:
            break
        out += chunk
        if len(out) > 2_000_000:
            break

    raw: dict = {}
    for ln in out.decode("utf-8", "replace").splitlines():
        ln = ln.strip()
        if "=" in ln:
            key, _, val = ln.partition("=")
            raw[key.strip()] = val.strip().strip('"')

    info["hostname"] = raw.get("HOSTNAME") or None
    info["os"] = raw.get("OS") or None
    if raw.get("CPU", "").isdigit():
        info["cpu"] = f"{raw['CPU']} vCPU"

    def _human_size(mb: str) -> Optional[str]:
        if not mb.isdigit():
            return None
        value = int(mb)
        return f"{value / 1024:.1f} GiB" if value >= 1024 else f"{value} MiB"

    info["ram"] = _human_size(raw.get("MEM_MB", ""))
    info["swap"] = _human_size(raw.get("SWAP_MB", ""))
    info["disk"] = _human_size(raw.get("DISK_MB", ""))

    up = raw.get("UPTIME_S", "")
    info["uptime"] = _human_uptime(int(up)) if up.isdigit() else None
    return info


def check_vps(vps: Vps, timeout: float, ping_only: bool,
              fetch_info: bool = True,
              deadline: Optional[float] = None) -> Result:
    """Check a single VPS and return a Result.

    ``deadline`` is an absolute ``time.monotonic()`` timestamp. Every phase
    (TCP / SSH login / spec fetch) is cut short when it passes, so a single
    box can never keep the whole run alive past the global budget.
    """
    base = dict(ip=vps.ip, port=vps.port, user=vps.user)
    start = time.monotonic()

    def _remaining() -> float:
        if deadline is None:
            return float("inf")
        return max(0.0, deadline - time.monotonic())

    def _skip(reason: str) -> Result:
        return Result(status="SKIPPED", detail=reason,
                      latency_ms=int((time.monotonic() - start) * 1000), **base)

    # 1) Is the port reachable at all? (always done, bounded by the timeout)
    eff = min(timeout, _remaining())
    if eff <= 0:
        return _skip("not checked (global deadline reached)")
    reachable, reason = _tcp_reachable(vps.ip, vps.port, eff)
    if not reachable:
        return Result(status="UNREACHABLE", detail=reason,
                      latency_ms=int((time.monotonic() - start) * 1000), **base)

    if ping_only:
        return Result(status="OK", detail="tcp port open",
                      latency_ms=int((time.monotonic() - start) * 1000), **base)

    # 2) Full SSH login test ----------------------------------------------- #
    if paramiko is None:
        return Result(status="ERROR",
                      detail="paramiko not installed (pip install paramiko)",
                      **base)

    eff = min(timeout, _remaining())
    if eff <= 0:
        return _skip("not checked (global deadline reached)")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=vps.ip,
            port=vps.port,
            username=vps.user,
            password=vps.password,
            timeout=eff,
            banner_timeout=eff,
            auth_timeout=eff,
            allow_agent=False,    # don't hang on local ssh-agent
            look_for_keys=False,  # don't try local private keys
        )
    except paramiko.AuthenticationException:
        return Result(status="AUTH_FAILED",
                      detail="username/password rejected", **base)
    except (socket.timeout, paramiko.SSHException) as exc:
        return Result(status="UNREACHABLE",
                      detail=f"ssh handshake failed: {exc}", **base)
    except Exception as exc:  # report any other failure cleanly
        return Result(status="ERROR", detail=str(exc), **base)

    try:
        info = _get_system_info(client, max_seconds=min(10.0, _remaining())) \
            if fetch_info else {
            "hostname": None, "os": None, "cpu": None, "ram": None,
            "disk": None, "swap": None, "uptime": None,
        }
    finally:
        client.close()

    return Result(status="OK",
                  detail="logged in successfully",
                  latency_ms=int((time.monotonic() - start) * 1000),
                  password=vps.password,
                  **base,
                  **info)


def run_checks(vps_list: List[Vps], timeout: float, ping_only: bool,
               workers: int, fetch_info: bool = True,
               on_result=None, deadline: float = 0.0) -> List[Result]:
    """Check every VPS in parallel, preserving input order in the output.

    If ``on_result`` is given it is called (on the main thread, one at a time)
    the moment each VPS finishes -- so you can log live and/or store a
    surviving box immediately, without waiting for the whole batch to finish.

    ``deadline`` (seconds) is a hard wall-clock budget for the whole batch.
    Once it is reached the run stops and any VPS that wasn't checked yet is
    reported as SKIPPED, so the run always finishes (and always returns a
    result for every input line).
    """
    results: List[Optional[Result]] = [None] * len(vps_list)
    workers = max(1, min(workers, max(1, len(vps_list))))
    deadline_abs = time.monotonic() + deadline if deadline > 0 else None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(check_vps, vps, timeout, ping_only, fetch_info,
                        deadline_abs): idx
            for idx, vps in enumerate(vps_list)
        }
        for fut in as_completed(futures):
            idx = futures[fut]
            r = fut.result()
            results[idx] = r
            if on_result is not None:
                try:
                    on_result(r)
                except Exception:
                    pass  # a logging/store hiccup must never abort the run
            if deadline_abs is not None and time.monotonic() >= deadline_abs:
                break
        for fut in futures:
            fut.cancel()

    # Anything left unprocessed gets a SKIPPED result so the caller always
    # receives one Result per input line.
    for idx, vps in enumerate(vps_list):
        if results[idx] is None:
            results[idx] = Result(
                ip=vps.ip, port=vps.port, user=vps.user,
                status="SKIPPED", detail="not checked (deadline reached)",
                latency_ms=0)
    return results


# --------------------------------------------------------------------------- #
# Persistence  (health history across runs -> "dead for N days")
# --------------------------------------------------------------------------- #
def _now() -> "datetime.datetime":
    return datetime.datetime.now()


def _iso(dt: "datetime.datetime") -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _human_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes and not days:
        parts.append(f"{minutes}m")
    if not parts:
        parts.append(f"{secs}s")
    return " ".join(parts)


def _parse_duration(text: str) -> int:
    """'30'->30s, '30s'->30, '5m'->300, '6h'->21600, '1d'->86400."""
    text = str(text).strip().lower()
    mult = 1
    for suffix, m in (("d", 86400), ("h", 3600), ("m", 60), ("s", 1)):
        if text.endswith(suffix):
            text, mult = text[:-1], m
            break
    try:
        return int(float(text) * mult)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"invalid interval {text!r} (use e.g. 30s, 5m, 6h, 1d)")


def load_state(path: Optional[str]) -> dict:
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def save_state(path: Optional[str], state: dict) -> None:
    if not path:
        return
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=2)
    except OSError:
        pass


def update_state_one(state: dict, r: Result,
                     now: "datetime.datetime") -> dict:
    """Fold a single result into the per-server health history."""
    now_iso = _iso(now)
    s = state.setdefault(r.label, {
        "first_seen": now_iso,
        "last_checked": now_iso,
        "last_alive": None,
        "first_dead": None,
        "consecutive_dead": 0,
        "total_checks": 0,
        "total_ok": 0,
        "last_status": None,
    })
    s["last_checked"] = now_iso
    s["last_status"] = r.status
    s["total_checks"] += 1
    if r.status == "SKIPPED":
        # deadline cut-off -- not a real result, don't count it at all
        s["total_checks"] -= 1
        return state
    if r.status == "OK":
        s["last_alive"] = now_iso
        s["first_dead"] = None
        s["consecutive_dead"] = 0
        s["total_ok"] += 1
    elif r.status == "UNREACHABLE":
        if s["consecutive_dead"] == 0:
            s["first_dead"] = now_iso
        s["consecutive_dead"] += 1
    # AUTH_FAILED / ERROR are ambiguous (the box is up) -> not counted as dead
    return state


def update_state(state: dict, results: List[Result],
                 now: "datetime.datetime") -> dict:
    """Fold this round's results into the per-server health history."""
    for r in results:
        update_state_one(state, r, now)
    return state


def _confirmed_dead(results: List[Result], state: dict, threshold: int) -> List[Result]:
    """Results that are dead AND have stayed dead for >= threshold checks."""
    return [r for r in results
            if r.status == "UNREACHABLE"
            and state.get(r.label, {}).get("consecutive_dead", 0) >= threshold]


def append_log(path: Optional[str], results: List[Result],
               state: dict, threshold: int) -> None:
    if not path:
        return
    confirmed = _confirmed_dead(results, state, threshold)
    lines = [f"===== {_iso(_now())}  ({len(results)} checked, "
             f"{sum(1 for r in results if r.ok)} ok, "
             f"{sum(1 for r in results if r.status == 'UNREACHABLE')} dead) ====="]
    for r in results:
        s = state.get(r.label, {})
        extra = ""
        if r.status == "UNREACHABLE" and s.get("consecutive_dead"):
            extra = (f"   [dead {s['consecutive_dead']}x, "
                     f"since {s.get('first_dead')}]")
        lines.append(f"  {r.status:<12} {r.label}  user={r.user}  {r.detail}{extra}")
    if confirmed:
        lines.append("  CONFIRMED DEAD (safe to delete):")
        for r in confirmed:
            s = state.get(r.label, {})
            lines.append(f"     - {r.label}  (dead {s.get('consecutive_dead')}x, "
                         f"since {s.get('first_dead')})")
    lines.append("")
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    except OSError:
        pass


def export_delete(path: Optional[str], results: List[Result],
                  state: dict, threshold: int) -> List[Result]:
    """Write the confirmed-dead servers to a ready-to-delete list file."""
    confirmed = _confirmed_dead(results, state, threshold)
    if not confirmed:
        return confirmed
    lines = [
        "# VPSes confirmed DEAD -- safe to delete",
        "# generated: " + _iso(_now()),
        "#",
    ]
    for r in confirmed:
        s = state.get(r.label, {})
        lines.append(f"{r.label}   # dead {s.get('consecutive_dead', '?')}x "
                     f"since {s.get('first_dead', '?')}")
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    except OSError:
        pass
    return confirmed


def working_line(r: Result) -> str:
    """One '<ip:port:user:pass>   |   <specs>' line for a working box."""
    specs = [p for p in (
        r.os,
        r.cpu,
        (f"{r.ram} RAM" if r.ram else None),
        (f"{r.disk} disk" if r.disk else None),
        (f"up {r.uptime}" if r.uptime else None),
        r.hostname,
        (f"{r.latency_ms} ms" if r.latency_ms is not None else None),
    ) if p]
    spec_str = ", ".join(specs) if specs else "working"
    creds = f"{r.ip}:{r.port}:{r.user}:{r.password or ''}"
    return f"{creds}   |   {spec_str}"


def _working_header_lines(now: Optional["datetime.datetime"] = None) -> List[str]:
    """Header lines written to the top of the working/live file."""
    return [
        "# WORKING VPSes  (alive + login OK)  --  keep these",
        "# generated: " + _iso(now or _now()),
        "#",
        "# format:  ip:port:user:pass   |   os, cpu, ram, disk, uptime, host",
    ]


def export_working(path: Optional[str], results: List[Result]) -> List[Result]:
    """Write the WORKING servers as '<ip:port:user:pass> | <specs>' lines so
    the credentials AND the box's specs (OS / CPU / RAM / disk / uptime) live
    together in ONE file -- no need to cross-reference the list file.
    """
    working = [r for r in results if r.ok]
    if not path or not working:
        return working
    lines = _working_header_lines()
    for r in working:
        lines.append(working_line(r))
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    except OSError:
        pass
    return working


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
class Style:
    """Tiny ANSI colour helper that auto-disables when not on a TTY."""

    enabled = sys.stdout.isatty() and "NO_COLOR" not in os.environ

    @classmethod
    def _wrap(cls, code: str, text: str) -> str:
        if not cls.enabled:
            return text
        return f"\x1b[{code}m{text}\x1b[0m"

    @classmethod
    def green(cls, t): return cls._wrap("32", t)
    @classmethod
    def red(cls, t): return cls._wrap("31", t)
    @classmethod
    def yellow(cls, t): return cls._wrap("33", t)
    @classmethod
    def dim(cls, t): return cls._wrap("2", t)
    @classmethod
    def bold(cls, t): return cls._wrap("1", t)


_STATUS_ICON = {
    "OK": "OK  ",
    "UNREACHABLE": "DEAD",
    "AUTH_FAILED": "AUTH",
    "ERROR": "ERR ",
}


def _color_for(status: str):
    return {
        "OK": Style.green,
        "UNREACHABLE": Style.red,
        "AUTH_FAILED": Style.yellow,
        "ERROR": Style.yellow,
    }.get(status, lambda t: t)


def _result_info(r: Result, state: Optional[dict]) -> str:
    """The right-hand 'info' text for a single result line."""
    state = state or {}
    if r.status == "OK":
        extra = []
        if r.os:
            extra.append(Style.green(r.os))
        if r.cpu:
            extra.append(Style.dim(r.cpu))
        if r.ram:
            extra.append(Style.dim(f"{r.ram} RAM"))
        if r.disk:
            extra.append(Style.dim(f"{r.disk} disk"))
        if r.uptime:
            extra.append(Style.dim(f"up {r.uptime}"))
        if r.hostname:
            extra.append(Style.dim(r.hostname))
        if r.latency_ms is not None:
            extra.append(Style.dim(f"{r.latency_ms} ms"))
        return "  ".join(extra) if extra else "working"

    s = state.get(r.label, {})
    if r.status == "UNREACHABLE" and s.get("consecutive_dead"):
        return (Style.yellow(r.detail) + "  "
                + Style.dim(f"[dead {s['consecutive_dead']}x, "
                            f"since {s.get('first_dead')}]"))
    return Style.yellow(r.detail)


def print_live_result(r: Result, state: Optional[dict] = None) -> None:
    """Print ONE result the moment its check finishes (live terminal log).

    Colour-coded: green = alive/working, red = dead/unreachable,
    yellow = auth failed or error. Printed live so you can watch each box
    resolve as it completes instead of waiting for the whole batch.
    """
    icon = _STATUS_ICON.get(r.status, r.status[:4])
    tag = _color_for(r.status)(f"[{icon}]")
    print(f"  {tag}  {r.label}  {r.user}  {_result_info(r, state)}", flush=True)


def print_start(total: int, ping_only: bool) -> None:
    """Printed once, before the checks start, so results stream in below it."""
    print()
    title = f"Checking {total} VPS" + ("" if total == 1 else "es")
    if ping_only:
        title += "  (ping-only mode)"
    print(Style.bold(title))
    print("-" * 78)


def print_report(results: List[Result], ping_only: bool,
                 state: Optional[dict] = None, threshold: int = 3) -> None:
    """The wrap-up: summary + which boxes are safe to delete.

    The per-server lines are printed live as each check finishes (see
    ``print_live_result`` / ``run_once``), so this only shows the final tally
    and the confirmed-dead list.
    """
    ok = [r for r in results if r.ok]
    dead = [r for r in results if r.status == "UNREACHABLE"]
    auth = [r for r in results if r.status == "AUTH_FAILED"]
    errors = [r for r in results if r.status == "ERROR"]
    skipped = [r for r in results if r.status == "SKIPPED"]

    print("-" * 78)
    if ping_only:
        summary = (f"Summary: {Style.green(str(len(ok)) + ' reachable')}, "
                   f"{Style.red(str(len(dead)) + ' unreachable')}")
    else:
        summary = (f"Summary: {Style.green(str(len(ok)) + ' working')}, "
                   f"{Style.red(str(len(dead)) + ' DEAD')}, "
                   f"{Style.yellow(str(len(auth)) + ' auth failed')}")
    if skipped:
        summary += (f", {Style.yellow(str(len(skipped)) + ' skipped')} "
                    f"(deadline reached)")
    if errors:
        summary += f", {Style.yellow(str(len(errors)) + ' error(s)')}"
    print(Style.bold(summary))

    # Point the user directly at the candidates to delete.
    state = state or {}
    confirmed = _confirmed_dead(results, state, threshold)
    if confirmed:
        print()
        print(Style.bold(Style.red(
            f"  SAFE TO DELETE  (dead for {threshold}+ consecutive checks):")))
        for r in confirmed:
            s = state.get(r.label, {})
            print(Style.red(f"    -> {r.label}   dead since {s.get('first_dead')} "
                            f"({s.get('consecutive_dead')} checks in a row)"))
    elif dead:
        print()
        print(Style.red(
            f"  Dead now, but not yet confirmed "
            f"(needs {threshold} dead checks in a row before delete):"))
        for r in dead:
            s = state.get(r.label, {})
            print(Style.red(f"    -> {r.label}  ({r.detail}) "
                            f"[dead {s.get('consecutive_dead', 1)}x]"))
    elif not ping_only and auth and not ok:
        print()
        print(Style.yellow(
            "  Note: no server accepted your credentials. If the VPSes are "
            "actually alive, double-check the user/password in the list file."
        ))
    print()


def _emit_progress(obj) -> None:
    """One compact JSON progress line per finished check (for --progress-json).

    Printed immediately with flush=True so a live reader (e.g. the bot) can
    update its UI as results stream in.
    """
    print(json.dumps(obj, separators=(",", ":")), flush=True)


def print_json(results: List[Result]) -> None:
    payload = {
        "total": len(results),
        "working": sum(1 for r in results if r.status == "OK"),
        "unreachable": sum(1 for r in results if r.status == "UNREACHABLE"),
        "auth_failed": sum(1 for r in results if r.status == "AUTH_FAILED"),
        "results": [asdict(r) for r in results],
    }
    print(json.dumps(payload, indent=2))


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Check a list of VPS servers over SSH and report which "
                    "are working and which are dead.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  python vps_checker.py vps_list.txt --timeout 6 --workers 16\n"
               "  python vps_checker.py --ping-only --json\n"
               "\n"
               "automation (so you never forget to delete a dead box):\n"
               "  python vps_checker.py vps_list.txt\n"
               "    -> a box dead 3 runs in a row lands in to_delete.txt\n"
               "  python vps_checker.py vps_list.txt --loop --interval 6h\n"
               "    -> keep checking forever, re-check every 6 hours\n"
               "  python vps_checker.py vps_list.txt --install-task --task-time 08:00\n"
               "    -> let Windows run it daily on its own\n"
               "  python vps_checker.py vps_list.txt --remove-task",
    )
    p.add_argument("file", nargs="?", default="vps_list.txt",
                   help="path to the VPS list file (default: vps_list.txt)")
    p.add_argument("-t", "--timeout", type=float, default=6.0,
                   help="per-connection timeout in seconds (default: 6)")
    p.add_argument("-w", "--workers", type=int, default=8,
                   help="number of parallel checks (default: 8)")
    p.add_argument("--deadline", type=float, default=0.0,
                   help="hard stop after N seconds; un-checked VPSes are "
                        "reported as SKIPPED (0 = no limit)")
    p.add_argument("--progress-json", action="store_true",
                   help="print one compact JSON progress line per finished "
                        "check, then a single-line summary (for live UIs)")
    p.add_argument("--ping-only", action="store_true",
                   help="only test TCP reachability, skip the SSH login")
    p.add_argument("--json", action="store_true",
                   help="print results as JSON instead of a table")

    # --- automation / not-forgetting-to-delete ---------------------------- #
    p.add_argument("--state", default="vps_state.json",
                   help="health-history file (default: vps_state.json)")
    p.add_argument("--log", default="vps_checker.log",
                   help="append-only audit log (default: vps_checker.log)")
    p.add_argument("--export-delete", default="to_delete.txt",
                   help="write confirmed-dead list (default: to_delete.txt)")
    p.add_argument("--export-working", default="working.txt",
                   help="write WORKING servers + their specs "
                        "(default: working.txt)")
    p.add_argument("--no-info", action="store_true",
                   help="skip gathering specs (OS / CPU / RAM / disk) of "
                        "working boxes (faster)")
    p.add_argument("--threshold", type=int, default=3,
                   help="consecutive DEAD checks before 'safe to delete' "
                        "(default: 3)")
    p.add_argument("--no-persist", action="store_true",
                   help="do not write state/log/export this run")
    p.add_argument("--loop", action="store_true",
                   help="keep checking forever (Ctrl+C to stop)")
    p.add_argument("--interval", type=_parse_duration, default=86400,
                   help="how often in --loop mode: 30s / 5m / 6h / 1d "
                        "(default: 1d)")

    # --- windows scheduled task ------------------------------------------- #
    p.add_argument("--install-task", action="store_true",
                   help="register a daily Windows Scheduled Task and exit")
    p.add_argument("--remove-task", action="store_true",
                   help="remove the Windows Scheduled Task and exit")
    p.add_argument("--task-name", default="VPS-Checker-Daily",
                   help="scheduled task name (default: VPS-Checker-Daily)")
    p.add_argument("--task-time", default="08:00",
                   help="daily start time HH:MM (default: 08:00)")
    return p


def _bat_path() -> str:
    """Absolute path of the wrapper batch file (next to this script)."""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "vps_checker_daily.bat")


def _write_bat(list_file: str, args) -> str:
    """Generate a wrapper .bat. Its *content* may be long, but the
    schtasks /TR value only holds this short path (avoids the 261-char limit)."""
    checker_dir = os.path.dirname(os.path.abspath(__file__))
    python = os.path.abspath(sys.executable) if sys.executable else "python"
    script = os.path.join(checker_dir, "vps_checker.py")
    lines = [
        "@echo off",
        f'cd /d "{checker_dir}"',
        f'"{python}" "{script}" "{os.path.abspath(list_file)}"'
        " --timeout 10 --workers 8"
        f' --state "{os.path.abspath(args.state)}"'
        f' --log "{os.path.abspath(args.log)}"'
        f' --export-delete "{os.path.abspath(args.export_delete)}"',
        "exit /b %ERRORLEVEL%",
    ]
    path = _bat_path()
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write("\r\n".join(lines) + "\r\n")
    return path


def install_task(args, list_file: str) -> int:
    try:
        bat = _write_bat(list_file, args)
    except OSError as exc:
        print(f"Could not write wrapper batch file: {exc}", file=sys.stderr)
        return 2

    cmd = ["schtasks", "/Create",
           "/SC", "DAILY", "/ST", args.task_time,
           "/TN", args.task_name,
           "/TR", f'"{bat}"',
           "/F"]
    print("Creating Windows Scheduled Task:")
    print(f"    name    : {args.task_name}")
    print(f"    schedule: daily at {args.task_time}")
    print(f"    wrapper : {bat}")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except OSError as exc:
        print(f"Could not run schtasks: {exc}", file=sys.stderr)
        return 2
    if proc.returncode != 0:
        print("schtasks failed:", (proc.stderr or proc.stdout).strip(),
              file=sys.stderr)
        return proc.returncode
    print(Style.green("  Scheduled task created. It will now run on its own."))
    print(f"  Remove it later with:  python {os.path.basename(__file__)} "
          f"--remove-task")
    return 0


def remove_task(args) -> int:
    cmd = ["schtasks", "/Delete", "/TN", args.task_name, "/F"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except OSError as exc:
        print(f"Could not run schtasks: {exc}", file=sys.stderr)
        return 2
    if proc.returncode != 0:
        print("schtasks failed:", (proc.stderr or proc.stdout).strip(),
              file=sys.stderr)
        return proc.returncode
    bat = _bat_path()
    if os.path.exists(bat):
        try:
            os.remove(bat)
        except OSError:
            pass
    print(Style.green(f"  Removed scheduled task '{args.task_name}'."))
    return 0


def run_once(args, state: dict, vps_list: List[Vps]) -> int:
    """One full check, done LIVE.

    As each VPS finishes it is:
      1. folded into the health history (so the running 'dead Nx' count is
         already current for the live log line),
      2. stored to the working/live file IMMEDIATELY if it is alive -- the
         good boxes are saved the moment they're found, not after the whole
         batch finishes, so an interrupted run still has every survivor, and
      3. printed to the terminal as a live, colour-coded log line.
    """
    now = _now()

    # Open the working file once for this round (header first) so each
    # surviving box can be appended the instant it's confirmed alive.
    live_handle = None
    if not args.no_persist and args.export_working:
        try:
            live_handle = open(args.export_working, "w", encoding="utf-8")
            live_handle.write("\n".join(_working_header_lines(now)) + "\n")
            live_handle.flush()
        except OSError:
            live_handle = None  # fall back to a single write at the end

    progress = {"done": 0, "working": 0, "dead": 0, "auth": 0, "skipped": 0}

    def on_result(r: Result) -> None:
        # 1) keep the health history current as we go (main thread, safe).
        update_state_one(state, r, now)
        # 2) store any surviving box to disk right now.
        if r.ok and live_handle is not None:
            try:
                live_handle.write(working_line(r) + "\n")
                live_handle.flush()  # hit disk immediately
            except OSError:
                pass
        # 3) live terminal line (skipped in --json so stdout stays valid JSON).
        if not args.json:
            print_live_result(r, state)
        # 4) live machine-readable progress line (for the bot's status msg).
        if args.progress_json:
            progress["done"] += 1
            st = r.status
            if st == "OK":
                progress["working"] += 1
            elif st == "UNREACHABLE":
                progress["dead"] += 1
            elif st == "AUTH_FAILED":
                progress["auth"] += 1
            elif st == "SKIPPED":
                progress["skipped"] += 1
            _emit_progress({"progress": True, **progress,
                            "total": len(vps_list),
                            "last": f"{st} {r.label}"})

    if not args.json:
        print_start(len(vps_list), args.ping_only)
    elif args.progress_json:
        _emit_progress({"progress": True, **progress,
                        "total": len(vps_list), "last": None})

    results = run_checks(vps_list, timeout=args.timeout,
                         ping_only=args.ping_only, workers=args.workers,
                         fetch_info=not args.no_info, on_result=on_result,
                         deadline=args.deadline)

    if live_handle is not None:
        try:
            live_handle.close()
        except OSError:
            pass
        # working file was written incrementally above -- nothing left to do.
    elif not args.no_persist and args.export_working:
        # Couldn't open it up front -> just write it all at the end.
        export_working(args.export_working, results)

    if not args.no_persist:
        save_state(args.state, state)
        append_log(args.log, results, state, args.threshold)
        export_delete(args.export_delete, results, state, args.threshold)

    if args.json:
        payload = {
            "checked_at": _iso(now),
            "total": len(results),
            "working": sum(1 for r in results if r.ok),
            "unreachable": sum(1 for r in results
                               if r.status == "UNREACHABLE"),
            "auth_failed": sum(1 for r in results
                               if r.status == "AUTH_FAILED"),
            "skipped": sum(1 for r in results if r.status == "SKIPPED"),
            "timed_out": any(r.status == "SKIPPED" for r in results),
            "safe_to_delete": [r.label
                               for r in _confirmed_dead(results, state,
                                                        args.threshold)],
            "results": [asdict(r) for r in results],
        }
        if args.progress_json:
            print(json.dumps(payload, separators=(",", ":")))
        else:
            print(json.dumps(payload, indent=2))
    else:
        print_report(results, args.ping_only, state=state,
                     threshold=args.threshold)

    # Exit code: 0 if everything is working, 1 otherwise (handy for a task).
    return 0 if all(r.ok for r in results) else 1


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    list_file = args.file

    # Scheduled-task management short-circuits the checker itself.
    if args.install_task or args.remove_task:
        if not os.name.startswith("nt"):
            print("Scheduled tasks are only available on Windows.",
                  file=sys.stderr)
            return 2
        return install_task(args, list_file) if args.install_task \
            else remove_task(args)

    if not args.ping_only and paramiko is None:
        print("paramiko is required for full SSH checks.\n"
              "Install it with:  pip install paramiko\n"
              "(or use --ping-only for a reachability-only check)",
              file=sys.stderr)
        return 2

    try:
        vps_list = load_vps(list_file)
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    if not vps_list:
        print(f"No VPS entries found in {list_file}.", file=sys.stderr)
        return 1

    state = {} if args.no_persist else load_state(args.state)

    if not args.loop:
        return run_once(args, state, vps_list)

    # --- continuous loop mode --------------------------------------------- #
    print(Style.bold(
        f"Loop mode: re-checking every {_human_duration(args.interval)} "
        f"(Ctrl+C to stop)"))
    try:
        while True:
            run_once(args, state, vps_list)
            print()
            print(Style.dim(f"  Sleeping {args.interval}s until next check..."))
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nStopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
