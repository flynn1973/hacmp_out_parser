#!/usr/bin/env python3.12
"""
hacmp_analyze.py - scan PowerHA SystemMirror (HACMP) hacmp.out logs for
errors and problems and print a readable report.

What it finds
  * Cluster events that FAILED or completed with a non-zero exit status
  * Problem events (config_too_long, event_error, node_down, network_down,
    fail_interface, swap_adapter, site_down, ...)
  * Events that were started but never completed (hung / log cut off)
  * Error and warning lines (ERROR:, failed, cannot, AIX message IDs such as
    0516-xxx, varyonvg/mount/fsck failures, timeouts, resource groups in ERROR
    state, ...)
  * Non-zero return codes in ksh trace output (with --trace)

Usage
  hacmp_analyze.py [/var/hacmp/log/hacmp.out ...] [options]

  Several files can be given (e.g. hacmp.out hacmp.out.1 ...). Without a file argument the default location
  /var/hacmp/log/hacmp.out is used. Use "-" to read from stdin.

Options
  -C N, --context N   show N lines of context around each error (default 0)
  --trace             also scan ksh "set -x" trace lines (noisier)
  --min-severity S    CRITICAL | ERROR | WARNING (default WARNING)
  --no-dedup          print every matching line instead of grouping duplicates
  --no-color          disable ANSI colours

Exit status: 0 = nothing found, 1 = warnings only, 2 = errors/critical found.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import deque
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import TextIO

DEFAULT_LOG = "/var/hacmp/log/hacmp.out"


class Severity(IntEnum):
    WARNING = 1
    ERROR = 2
    CRITICAL = 3


# --------------------------------------------------------------------------- #
# Patterns
# --------------------------------------------------------------------------- #

# Leading timestamps seen in hacmp.out across PowerHA versions:
#   "Mar 12 10:15:01 EVENT START: ..."
#   "Mar 12 2024 10:15:01 EVENT START: ..."
#   "Tue Mar 12 10:15:01 CET 2024"
TS_RE = re.compile(
    r"^(?:(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+)?"
    r"(?P<ts>(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+"
    r"(?:\d{4}\s+)?\d{2}:\d{2}:\d{2}(?:\s+[A-Z]{2,5}\s+\d{4})?)"
)

EVENT_START_RE = re.compile(r"EVENT START:\s*(?P<name>\S+)\s*(?P<args>.*?)\s*$")
EVENT_DONE_RE = re.compile(r"EVENT COMPLETED:\s*(?P<name>\S+)\s*(?P<args>.*?)\s*$")
# Formats seen: "EVENT FAILED: 1: node_up nodeA 1" and "EVENT FAILED: node_up nodeA 1"
EVENT_FAIL_RE = re.compile(
    r"EVENT FAILED:\s*(?:(?P<rc0>-?\d+)\s*:\s*)?(?P<name>\S+)\s*(?P<args>.*?)\s*$"
)

# ksh trace lines produced by "set -x" in PowerHA event scripts, e.g.
#   +rg1:cl_activate_vgs[256] RC=1
#   :node_up[123] [[ -z '' ]]
#   + cl_RMupdate ...
TRACE_RE = re.compile(r"^(?:\+\S*|:\S+\[\d+\])(?:\s|$)|^\+\s")

# Events whose mere presence indicates a problem.
PROBLEM_EVENTS: dict[str, tuple[Severity, str]] = {
    "config_too_long": (Severity.CRITICAL, "Event processing hung / took too long (config_too_long)"),
    "event_error": (Severity.CRITICAL, "Cluster event error - cluster manager detected a failed event"),
    "node_down": (Severity.WARNING, "Node left the cluster"),
    "site_down": (Severity.ERROR, "Site went down"),
    "network_down": (Severity.ERROR, "Network went down"),
    "network_down_local": (Severity.ERROR, "Network went down on local node"),
    "fail_interface": (Severity.ERROR, "Network interface failed"),
    "fail_standby": (Severity.ERROR, "Standby/boot adapter failed"),
    "swap_adapter": (Severity.WARNING, "Service IP swapped to another adapter"),
    "swap_address": (Severity.WARNING, "IP address swap"),
    "server_down": (Severity.ERROR, "Application server/controller down"),
    "server_restart": (Severity.WARNING, "Application server restarted by monitor"),
    "resource_state_change": (Severity.WARNING, "Resource state change (e.g. selective fallover)"),
    "fail_node": (Severity.ERROR, "Node failure"),
    "split_merge_prompt": (Severity.CRITICAL, "Cluster split/merge detected"),
    "cluster_split": (Severity.CRITICAL, "Cluster partition / split"),
    "cluster_merge": (Severity.WARNING, "Cluster merge after split"),
    "join_cleanup": (Severity.WARNING, "Join cleanup"),
}


@dataclass(frozen=True, slots=True)
class Rule:
    category: str
    severity: Severity
    regex: re.Pattern[str]
    in_trace: bool = False  # also apply to ksh trace lines without --trace


def _r(p: str) -> re.Pattern[str]:
    return re.compile(p, re.IGNORECASE)


# Ordered: first match wins, so put specific rules first.
RULES: list[Rule] = [
    Rule("cluster", Severity.CRITICAL, _r(r"config_too_long|has been running recovery program"), True),
    Rule("cluster", Severity.CRITICAL, _r(r"\bpartition(?:ed)?\b.*\bcluster\b|\bsplit[- ]brain\b|\bdomain merge\b"), True),
    Rule("cluster", Severity.CRITICAL, _r(r"\bhalt(?:ing)? (?:the )?node\b|\bnode (?:will be )?halted\b|\bdead man switch\b|\bDMS\b timeout"), True),
    Rule("resource group", Severity.ERROR, _r(r"^\s*\S+\s+(?:ERROR|OFFLINE due to \w+)\b|\b(?:resource group|RG)\b.*\bERROR\b|\bERROR\b.*\bresource group\b|\bstate\b.*\bERROR\b"), True),
    Rule("resource group", Severity.ERROR, _r(r"\b(?:acquisition|release) of .* failed\b|\bfailed to (?:acquire|release|bring|move)\b"), True),
    Rule("LVM", Severity.ERROR, _r(r"\b05(?:16|11|13|17)-\d{3,4}\b"), True),  # LVM message IDs
    Rule("LVM", Severity.ERROR, _r(r"varyonvg.*(?:fail|error|cannot)|unable to vary\s?on|cl_activate_vgs.*(?:fail|error)|\bvaryon(?:vg)? failed\b"), True),
    Rule("LVM", Severity.ERROR, _r(r"\bquorum\b.*\b(?:lost|not available)\b|\bmissing\b.*\b(?:PV|disk|physical volume)s?\b|\bstale partitions?\b"), True),
    Rule("disk", Severity.ERROR, _r(r"\breserv(?:e|ation)\b.*\b(?:conflict|fail)|\bSCSI\b.*\b(?:error|reservation)\b|\bdisk fencing\b.*fail"), True),
    Rule("filesystem", Severity.ERROR, _r(r"\bfsck\b.*(?:fail|error|unrecoverable)|\bmount\b.*(?:fail|error)|\bumount\b.*(?:fail|busy|error)|\bdevice busy\b|cl_activate_fs.*(?:fail|error)|cl_deactivate_fs.*(?:fail|error)"), True),
    Rule("filesystem", Severity.ERROR, _r(r"\b0506-\d{3}\b|\bfuser\b.*\bkill"), True),
    Rule("filesystem", Severity.ERROR, _r(r"No space left on device|file system (?:is )?full"), True),
    Rule("NFS", Severity.ERROR, _r(r"\bNFS\b.*(?:fail|error|not responding|stale)|exportfs.*(?:fail|error)"), True),
    Rule("network", Severity.ERROR, _r(r"\b(?:ifconfig|route|arp)\b.*(?:fail|error|cannot)|\bIP address\b.*(?:fail|conflict|already in use)|duplicate IP|\bswap_adapter\b.*fail"), True),
    Rule("network", Severity.WARNING, _r(r"\bnetwork\b.*\bdown\b|\binterface\b.*\bdown\b|\badapter\b.*\b(?:down|failed)\b"), False),
    Rule("application", Severity.ERROR, _r(r"\b(?:application|app) (?:server|controller|monitor)\b.*(?:fail|error|could not|unable)|\bstart_server\b.*(?:fail|error)|\bstop_server\b.*(?:fail|error)|\bmonitor\b.*\bfailure\b"), True),
    Rule("CAA/RSCT", Severity.ERROR, _r(r"\bCAA\b.*(?:fail|error|not running)|\brepository disk\b.*(?:fail|error|lost|unavailable)|\bclcomd\b.*(?:fail|error|not running)|\brsct\b.*(?:fail|error)|\bgrpsvcs\b.*(?:fail|error)"), True),
    Rule("timeout", Severity.ERROR, _r(r"\btimed? ?out\b|\btimeout (?:expired|reached|occurred)\b"), False),
    Rule("permission", Severity.ERROR, _r(r"Permission denied|not owner|Operation not permitted"), False),
    Rule("general", Severity.ERROR, _r(r"!{3,}\s*ERROR\s*!{3,}|^\s*\**\s*ERROR\b|\bERROR\s*:|\bERROR\s+\d+\b|\bFATAL\b|\bfatal error\b|\bcore dump(?:ed)?\b|\bSegmentation fault\b"), True),
    Rule("general", Severity.ERROR, _r(r"\bfailed\b|\bfailure\b|\bunable to\b|\bcannot\b|\bcould not\b|\bcouldn't\b|\babort(?:ed|ing)?\b"), False),
    Rule("general", Severity.WARNING, _r(r"\bnot found\b|No such file or directory|\bnot available\b|\bnot responding\b|\bnot running\b"), False),
    Rule("general", Severity.WARNING, _r(r"!{3,}\s*WARNING\s*!{3,}|\bWARNING\s*:|^\s*WARNING\b"), True),
]

# Trace-only rule: a non-zero rc assignment, e.g. "+rg1:cl_activate_fs[300] RC=1"
TRACE_RC_RE = re.compile(r"\b(?:RC|rc|STATUS|status|retcode|exit_status)=(?P<rc>[1-9]\d*)\s*$")

# Lines that match the rules above but are known noise.
NOISE_RE = re.compile(
    r"|".join(
        [
            r"\berror(?:s)?\s*=\s*0\b",
            r"\b0 errors?\b",
            r"\bno errors?\b",
            r"\bwithout errors?\b",
            r"\bfailed\s*=\s*0\b",
            r"\bfailure_?(?:notification|action|method)\b",
            r"\bERROR_?(?:FILE|LOG|MSG|CODE)\s*=",
            r"^\s*#",  # comments in dumped scripts
        ]
    ),
    re.IGNORECASE,
)


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class Event:
    name: str
    args: str
    file: str
    start_line: int
    start_ts: str | None
    end_line: int | None = None
    end_ts: str | None = None
    rc: int | None = None
    failed: bool = False
    depth: int = 0


@dataclass(slots=True)
class Finding:
    severity: Severity
    category: str
    message: str
    file: str
    line: int
    timestamp: str | None
    event: str | None
    context: list[str] = field(default_factory=list)
    count: int = 1
    last_line: int | None = None


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #


def open_log(path: str) -> TextIO:
    if path == "-":
        return open(sys.stdin.fileno(), "r", encoding="utf-8", errors="replace", closefd=False)
    return Path(path).open("r", encoding="utf-8", errors="replace")


def _parse_rc(args: str) -> tuple[str, int | None]:
    """'nodeA rg1 0' -> ('nodeA rg1', 0)"""
    parts = args.rsplit(None, 1)
    if parts and re.fullmatch(r"-?\d+", parts[-1]):
        return (parts[0] if len(parts) > 1 else ""), int(parts[-1])
    return args, None


class HacmpParser:
    def __init__(self, *, context: int, trace: bool) -> None:
        self.context = context
        self.trace = trace
        self.events: list[Event] = []
        self.findings: list[Finding] = []
        self._stack: list[Event] = []

    # -- helpers -----------------------------------------------------------
    def _current_event(self) -> str | None:
        if not self._stack:
            return None
        e = self._stack[-1]
        return f"{e.name} {e.args}".strip()

    def _close_event(self, name: str, args: str, rc: int | None, failed: bool,
                     lineno: int, ts: str | None) -> Event:
        # Find the most recent open event with the same name (events nest).
        for i in range(len(self._stack) - 1, -1, -1):
            if self._stack[i].name == name:
                ev = self._stack.pop(i)
                # Anything opened after it and still open is abandoned;
                # leave those to be reported as "not completed".
                break
        else:
            ev = Event(name, args, self._file, lineno, None, depth=len(self._stack))
            self.events.append(ev)
        ev.end_line, ev.end_ts, ev.rc = lineno, ts, rc
        ev.failed = failed or (rc is not None and rc != 0)
        return ev

    # -- main loop ---------------------------------------------------------
    def parse(self, path: str) -> None:
        self._file = path
        last_ts: str | None = None
        before: deque[str] = deque(maxlen=self.context)
        pending_after: list[tuple[Finding, int]] = []  # finding, lines still needed

        with open_log(path) as fh:
            for lineno, raw in enumerate(fh, 1):
                line = raw.rstrip("\n")

                # Feed "after" context to findings waiting for it
                if pending_after:
                    still: list[tuple[Finding, int]] = []
                    for f, n in pending_after:
                        f.context.append(f"{lineno:>7}  {line}")
                        if n > 1:
                            still.append((f, n - 1))
                    pending_after = still

                if (m := TS_RE.match(line)):
                    last_ts = m["ts"]

                new = self._handle_line(line, lineno, last_ts)
                for f in new:
                    if self.context:
                        start = lineno - len(before)
                        f.context = [f"{start + i:>7}  {l}" for i, l in enumerate(before)]
                        f.context.append(f"{lineno:>7}> {line}")
                        pending_after.append((f, self.context))
                    self.findings.append(f)
                before.append(line)

        # Events still open at end of this file
        for ev in self._stack:
            self.findings.append(Finding(
                Severity.WARNING, "event",
                f"Event never completed: {ev.name} {ev.args}".strip()
                + " (hung, node crashed/halted, or log rotated)",
                ev.file, ev.start_line, ev.start_ts, None))
        self._stack.clear()

    def _handle_line(self, line: str, lineno: int, ts: str | None) -> list[Finding]:
        out: list[Finding] = []

        # ---- cluster event bookkeeping ----------------------------------
        if (m := EVENT_START_RE.search(line)) and not TRACE_RE.match(line):
            ev = Event(m["name"], m["args"], self._file, lineno, ts, depth=len(self._stack))
            self.events.append(ev)
            self._stack.append(ev)
            if (pe := PROBLEM_EVENTS.get(ev.name)):
                sev, desc = pe
                out.append(Finding(sev, "event", f"{desc}: {ev.name} {ev.args}".strip(),
                                   self._file, lineno, ts, self._current_event()))
            return out

        if (m := EVENT_FAIL_RE.search(line)) and not TRACE_RE.match(line):
            args, rc = _parse_rc(m["args"])
            if m["rc0"] is not None:
                rc = int(m["rc0"])
            ev = self._close_event(m["name"], args, rc, True, lineno, ts)
            out.append(Finding(Severity.CRITICAL, "event",
                               f"EVENT FAILED: {ev.name} {ev.args}".strip() + f" (rc={rc})",
                               self._file, lineno, ts, self._current_event()))
            return out

        if (m := EVENT_DONE_RE.search(line)) and not TRACE_RE.match(line):
            args, rc = _parse_rc(m["args"])
            ev = self._close_event(m["name"], args, rc, False, lineno, ts)
            if ev.failed:
                out.append(Finding(Severity.CRITICAL, "event",
                                   f"Event completed with non-zero exit status: "
                                   f"{ev.name} {ev.args}".strip() + f" (rc={rc})",
                                   self._file, lineno, ts, self._current_event()))
            return out

        # ---- error / warning lines --------------------------------------
        if not line.strip() or NOISE_RE.search(line):
            return out

        is_trace = bool(TRACE_RE.match(line))

        if is_trace and self.trace and (m := TRACE_RC_RE.search(line)):
            out.append(Finding(Severity.WARNING, "return code",
                               f"Non-zero return code (rc={m['rc']}): {line.strip()}",
                               self._file, lineno, ts, self._current_event()))
            return out

        for rule in RULES:
            if is_trace and not (self.trace or rule.in_trace):
                continue
            if is_trace and not self.trace and not _trace_is_message(line):
                # In trace mode only accept lines that print a message.
                continue
            if rule.regex.search(line):
                out.append(Finding(rule.severity, rule.category, line.strip(),
                                   self._file, lineno, ts, self._current_event()))
                break
        return out


_MSG_CMD_RE = re.compile(r"\b(?:cl_log|cl_echo|dspmsg|echo|print|cl_msg|logger)\b")


def _trace_is_message(line: str) -> bool:
    """A trace line that emits a message (cl_log/cl_echo/dspmsg/echo ...)."""
    return bool(_MSG_CMD_RE.search(line))


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #


_NORM_RE = re.compile(r"\b\d+\b|0x[0-9a-fA-F]+")


def dedup(findings: list[Finding]) -> list[Finding]:
    """Group identical messages (numbers normalised) inside the same category."""
    groups: dict[tuple, Finding] = {}
    for f in findings:
        if f.category == "event":  # each event occurrence matters
            key = (id(f),)
        else:
            msg = TS_RE.sub("", f.message)
            key = (f.file, f.category, f.severity, _NORM_RE.sub("#", msg))
        if (g := groups.get(key)) is None:
            groups[key] = f
        else:
            g.count += 1
            g.last_line = f.line
    return list(groups.values())


class Color:
    def __init__(self, enabled: bool) -> None:
        self.on = enabled

    def __call__(self, code: str, s: str) -> str:
        return f"\033[{code}m{s}\033[0m" if self.on else s


SEV_COLOR = {Severity.CRITICAL: "1;31", Severity.ERROR: "31", Severity.WARNING: "33"}


def print_report(files: list[str], events: list[Event], findings: list[Finding],
                 c: Color) -> None:
    bar = "=" * 78
    print(c("1", bar))
    print(c("1", " PowerHA hacmp.out analysis"))
    print(c("1", bar))
    print(f" Files analysed : {', '.join(files)}")
    print(f" Events found   : {len(events)}")
    failed = [e for e in events if e.failed]
    print(f" Failed events  : {c('1;31', str(len(failed))) if failed else '0'}")
    by_sev = {s: sum(f.count for f in findings if f.severity == s) for s in Severity}
    print(" Findings       : " + ", ".join(
        f"{c(SEV_COLOR[s], s.name)}={by_sev[s]}" for s in sorted(Severity, reverse=True)))

    # --- event summary ----------------------------------------------------
    if events:
        print("\n" + c("1", "-- Event timeline (top-level events, failures marked) " + "-" * 23))
        for e in events:
            if e.depth > 0 and not e.failed:
                continue
            status = ("FAILED" if e.failed else
                      "OK" if e.rc == 0 else
                      "NOT COMPLETED" if e.end_line is None else f"rc={e.rc}")
            col = "1;31" if e.failed else "33" if e.end_line is None else "32"
            indent = "  " * e.depth
            ts = e.start_ts or "-"
            print(f" {ts:<21} {c(col, f'{status:<13}')} {indent}{e.name} {e.args}"
                  f"  [{Path(e.file).name}:{e.start_line}]")

    # --- findings by category --------------------------------------------
    if not findings:
        print("\n" + c("32", "No errors or problems found."))
        return

    print("\n" + c("1", "-- Problems found " + "-" * 60))
    cats: dict[str, list[Finding]] = {}
    for f in sorted(findings, key=lambda f: (-f.severity, f.file, f.line)):
        cats.setdefault(f.category, []).append(f)

    for cat in sorted(cats, key=lambda k: -max(f.severity for f in cats[k])):
        items = cats[cat]
        print("\n" + c("1;4", f"[{cat.upper()}]") + f"  ({sum(f.count for f in items)} occurrence(s))")
        for f in sorted(items, key=lambda f: (f.file, f.line)):
            sev = c(SEV_COLOR[f.severity], f"{f.severity.name:<8}")
            loc = f"{Path(f.file).name}:{f.line}"
            if f.count > 1:
                loc += f"  (x{f.count}, last at line {f.last_line})"
            print(f"  {sev} {loc}" + (f"  {f.timestamp}" if f.timestamp else ""))
            print(f"           {f.message}")
            if f.event:
                print(c("2", f"           during event: {f.event}"))
            if f.context:
                for l in f.context:
                    print(c("2", f"         {l}"))
                print()


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Parse PowerHA hacmp.out and report errors and problems.")
    ap.add_argument("files", nargs="*", default=[DEFAULT_LOG],
                    help=f"hacmp.out file(s), '-' for stdin (default {DEFAULT_LOG})")
    ap.add_argument("-C", "--context", type=int, default=0, metavar="N",
                    help="lines of context to show around each finding")
    ap.add_argument("--trace", action="store_true",
                    help="also scan ksh 'set -x' trace lines (more findings, more noise)")
    ap.add_argument("--min-severity", type=str.upper, default="WARNING",
                    choices=[s.name for s in Severity])
    ap.add_argument("--no-dedup", action="store_true", help="do not group repeated messages")
    ap.add_argument("--no-color", action="store_true", help="disable colours")
    args = ap.parse_args(argv)

    parser = HacmpParser(context=max(0, args.context), trace=args.trace)
    files_ok: list[str] = []
    for path in args.files:
        try:
            parser.parse(path)
            files_ok.append(path)
        except OSError as exc:
            print(f"error: cannot read {path}: {exc}", file=sys.stderr)
    if not files_ok:
        return 3

    min_sev = Severity[args.min_severity]
    findings = [f for f in parser.findings if f.severity >= min_sev]
    if not args.no_dedup:
        findings = dedup(findings)

    color = Color(not args.no_color and sys.stdout.isatty())
    print_report(files_ok, parser.events, findings, color)

    worst = max((f.severity for f in findings), default=None)
    return 0 if worst is None else 1 if worst == Severity.WARNING else 2


if __name__ == "__main__":
    sys.exit(main())
