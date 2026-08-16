#!/usr/bin/env python3
"""extract_vps.py -- pull clean 'ip:port:user:pass' entries out of a messy .txt.

A messy credentials file usually has one box per line, in ALL sorts of shapes:

    https://163.61.230.214/:Admin:Sonu@321
    MY 72.62.195.50:root:P@ssw0rd#gem
    72.62.195.50:root:P@ssw0rd#gem
    root@163.61.230.214:mySecret
    http://192.168.1.1/cgi-bin/luci:root:admin

This tool normalises each line to exactly:  ip:port:user:pass
(the port defaults to 22 when it is not present) and writes them, one per
line, to a clean list file (default: vps_list.txt).

The two halves of the "environment":
    1) extract_vps.py  -> messy.txt   becomes   clean ip:port:user:pass list
    2) vps_checker.py  -> that list   becomes   working.txt (the live ones)

Run it in two steps, or in one:
    python extract_vps.py messy.txt              # -> writes vps_list.txt
    python vps_checker.py                        # -> checks it -> working.txt

    python extract_vps.py messy.txt --check      # both, in one command

Other options:
    python extract_vps.py messy.txt -o clean.txt # custom output file
    python extract_vps.py messy.txt --stdout-only  # just print, no file
"""

import argparse
import os
import re
import subprocess
import sys

DEFAULT_PORT = 22

# --- host patterns ---------------------------------------------------------- #
_IPV4 = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
_HOSTNAME = (
    r"\b[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,}\b"
)
_USER_CHARS = r"[A-Za-z0-9._\-]"

# user@domain  (used only when there is no IPv4 on the line)
_SSH_DOMAIN_RE = re.compile(r"(" + _USER_CHARS + r"+)@(" + _HOSTNAME + r")")
_IP_RE = re.compile(_IPV4)
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")


def _is_num(s: str) -> bool:
    """True only for a plain ASCII integer ('22', '2222', ...).

    Deliberately stricter than str.isdigit(), which also returns True for
    unicode digits such as superscripts ('⁰','¹') that int() cannot parse.
    """
    s = s.strip()
    return s.isascii() and s.isdigit()


def _parse_after_host(tail: str):
    """Parse what follows the host in the 'host ... :user:pass' style.

    Returns (port, user, password).  Handles a leading URL path and/or a
    numeric port, e.g.:
        ''                       -> (None, '', '')
        ':root:pass'             -> (None, 'root', 'pass')
        ':2222:root:pass'        -> (2222, 'root', 'pass')
        '/cgi-bin/luci:root:a'   -> (None, 'root', 'a')
        '/:Admin:Sonu@321'       -> (None, 'Admin', 'Sonu@321')
    """
    segs = tail.split(":")
    i = 0
    while i < len(segs) and segs[i].strip() == "":
        i += 1
    if i < len(segs) and "/" in segs[i]:          # drop a URL path segment
        i += 1
    port = None
    if i < len(segs) and _is_num(segs[i]):            # numeric -> the port
        port = int(segs[i].strip())
        i += 1
    if i < len(segs):
        user = segs[i].strip()
        password = ":".join(segs[i + 1:]).strip()   # keep ':' inside password
    else:
        user, password = "", ""
    return port, user, password


def _parse_after_ssh(tail: str):
    """Parse what follows the host in the 'user@host[:port][:pass]' style.

    There is no user after the host here (it was before the '@'), so the tail
    is only an optional port followed by the password.  Returns (port, password).
    """
    segs = tail.split(":")
    i = 0
    while i < len(segs) and segs[i].strip() == "":
        i += 1
    port = None
    if i < len(segs) and _is_num(segs[i]):
        port = int(segs[i].strip())
        i += 1
    password = ":".join(segs[i:]).strip() if i < len(segs) else ""
    return port, password


def extract_one(line: str):
    """Return a clean 'ip:port:user:pass' string, or None if the line holds no
    usable credential."""
    s = line.strip().strip("'\"")
    if not s or s.startswith("#") or s.startswith(";"):
        return None
    s = _SCHEME_RE.sub("", s).strip()          # drop http://, https://, ssh:// ...

    host = port = user = password = None
    mi = _IP_RE.search(s)

    if mi:
        ip = mi.group(0)
        if mi.start() >= 1 and s[mi.start() - 1] == "@":
            # 'user@IP'  -- the user sits right before the '@'
            at = mi.start() - 1
            j = at
            while j > 0 and re.match(_USER_CHARS, s[j - 1]):
                j -= 1
            user = s[j:at]
            host = ip
            port, password = _parse_after_ssh(s[mi.end():])
        else:
            # 'IP ... :user:pass'  (a path / port may sit in between)
            host = ip
            port, user, password = _parse_after_host(s[mi.end():])
    else:
        # IP-only policy: no real IPv4/IPv6 address on this line means it is not
        # a VPS credential. This rejects hostnames/emails/protocols such as
        # 'gmail.com:22:...', 'PK https:22:...', 'decouvrir.internal:22:...'.
        return None

    if not host or not user:
        return None
    if host.startswith("-") or host.endswith("."):
        return None
    port = port or DEFAULT_PORT
    return f"{host}:{port}:{user}:{password}"


def extract_file(path: str, dedupe: bool = True):
    """Read the messy file and return a list of clean 'ip:port:user:pass' lines."""
    entries, seen = [], set()
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, 1):
            try:
                entry = extract_one(raw)
            except Exception as exc:              # one bad line must not kill the run
                print("skipping line {}: {} ({})".format(lineno, raw.strip(), exc),
                      file=sys.stderr)
                continue
            if not entry:
                continue
            if dedupe:
                # same host + same user (ignore port differences / extra path junk)
                host, _port, user = entry.split(":", 2)
                key = (host.lower(), user)
                if key in seen:
                    continue
                seen.add(key)
            entries.append(entry)
    return entries


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Extract clean 'ip:port:user:pass' lines from a messy .txt "
                    "so you can feed them straight into vps_checker.py.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="pipeline:\n"
               "  python extract_vps.py messy.txt     # -> vps_list.txt\n"
               "  python vps_checker.py               # -> working.txt\n"
               "or in one command:\n"
               "  python extract_vps.py messy.txt --check\n",
    )
    ap.add_argument("input", nargs="?", default="messy.txt",
                    help="messy credentials file (default: messy.txt)")
    ap.add_argument("-o", "--output", default="vps_list.txt",
                    help="where to write the clean list (default: vps_list.txt)")
    ap.add_argument("--stdout-only", action="store_true",
                    help="print the list but do not write any file")
    ap.add_argument("--keep-dupes", action="store_true",
                    help="do not collapse duplicate host:user entries")
    ap.add_argument("--check", action="store_true",
                    help="after extracting, run vps_checker.py on the result")
    ap.add_argument("-q", "--quiet", action="store_true",
                    help="do not print the extracted list to stdout")
    args = ap.parse_args(argv)

    if not os.path.isfile(args.input):
        sys.exit("input file not found: {}\n"
                 "(pass the messy .txt as the first argument)".format(args.input))

    entries = extract_file(args.input, dedupe=not args.keep_dupes)

    if not args.quiet:
        print("Extracted {} credential(s) from '{}'".format(len(entries), args.input))
        print("-" * 64)
        for e in entries:
            print(e)
        print("-" * 64)

    if args.stdout_only:
        print("(--stdout-only: no file written)")
    else:
        with open(args.output, "w", encoding="utf-8") as fh:
            for e in entries:
                fh.write(e + "\n")
        print("Wrote {} line(s) -> {}".format(len(entries), args.output))
        if not args.check:
            print("Next:  python vps_checker.py")

    if args.check:
        print("Running checker...")
        subprocess.call([sys.executable, "vps_checker.py"])


if __name__ == "__main__":
    main()
