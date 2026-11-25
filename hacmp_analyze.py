#!/opt/freeware/bin/python3
"""
hacmp_analyze.py - scan PowerHA SystemMirror (HACMP) hacmp.out logs for
errors and problems and print a readable report.

What it finds
  * Cluster events that FAILED or completed with a non-zero exit status
  * Problem events (config_too_long, event_error, node_down, network_down,
    fail_interface, swap_adapter, site_down, ...)
  * Events that were started but never completed (hung / log cut off)
  * LVM volume group events from clevmgrd (PV_REMOVED, PV_ADDED, ...)
  * Error and warning lines (ERROR:, failed, cannot, AIX message IDs such as
    0516-xxx, varyonvg/mount/fsck failures, SRC errors, timeouts, resource
    groups in ERROR state, ...)
  * Non-zero return codes in ksh trace output (with --trace)

Usage
  hacmp_analyze.py [/var/hacmp/log/hacmp.out ...] [options]

  Several files can be given (e.g. hacmp.out hacmp.out.1 ...). Rotated copies
  of the same log are put in chronological order automatically (.N ... .1,
  then the live file) so events spanning a rotation are matched up; use
  --keep-order to disable this. Without a file argument the default location
  /var/hacmp/log/hacmp.out is used. Use "-" to read from stdin.

  The <LAT>|...|</LAT> lines that PowerHA 7.x writes next to the human-
  readable lines are duplicates; they are skipped, but their ISO timestamps
  are used for lines that have no timestamp of their own.

Options
  -C N, --context N   show N lines of context around each error (default 0)
  --trace             also scan ksh "set -x" trace lines (noisier)
  --min-severity S    CRITICAL | ERROR | WARNING (default WARNING)
  --no-dedup          print every matching line instead of grouping duplicates
  --keep-order        analyse files in the order given (no rotation sorting)
  --no-color          disable ANSI colours

Requires Python 3.8 or later.

Exit status: 0 = nothing found, 1 = warnings only, 2 = errors/critical found,
             3 = none of the files could be read.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
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
    r"(?P<ts>(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(?P<day>\d{1,2})\s+"
    r"(?:(?P<y1>\d{4})\s+)?(?P<time>\d{2}:\d{2}:\d{2})(?:\s+[A-Z]{2,5}\s+(?P<y2>\d{4}))?)"
)


def _norm_ts(m: re.Match[str]) -> str:
    """All three formats -> 'Oct 24 2026 18:42:20' (or 'Oct 24 18:42:20' without year)."""
    year = m["y1"] or m["y2"]
    return f"{m['mon']} {int(m['day']):02d} " + (f"{year} " if year else "") + m["time"]

# PowerHA 7.x machine-readable duplicates:
#   <LAT>|2026-10-24T18:42:20|20855|EVENT START: admin_op ...|</LAT>
#   <LAT>|EV_SUM_SEARCHON_STR|...|</LAT>
LAT_RE = re.compile(r"^<LAT>\|(?:(?P<iso>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)[.\d]*\|)?")

EVENT_START_RE = re.compile(r"EVENT START:\s*(?P<name>\S+)\s*(?P<args>.*?)\s*$")
EVENT_DONE_RE = re.compile(r"EVENT COMPLETED:\s*(?P<name>\S+)\s*(?P<args>.*?)\s*$")
# Formats seen: "EVENT FAILED: 1: node_up nodeA 1" and "EVENT FAILED: node_up nodeA 1"
EVENT_FAIL_RE = re.compile(
    r"EVENT FAILED:\s*(?:(?P<rc0>-?\d+)\s*:\s*)?(?P<name>\S+)\s*(?P<args>.*?)\s*$"
)

# ksh trace lines produced by "set -x" in PowerHA event scripts, e.g.
#   +rg1:cl_activate_vgs[256] RC=1
#   :node_up[123] [[ -z '' ]]
#   :cl_pvo(1.241):XAPvg[varyonp:549] : comment     (7.x PS4 with timings)
#   + cl_RMupdate ...
TRACE_RE = re.compile(r"^(?:\+\S*|:\S+\[[^\]\s]+\])(?:\s|$)|^\+\s")

# clevmgrd LVM notifications, e.g.
#   volumeGroupEvent: XIPvg PV_REMOVED 1
#   clevmgrd: volumeGroupEvent: XIPvg PV_ADDED 1: flooded 5 times
VG_EVENT_RE = re.compile(r"\bvolumeGroupEvent:\s+(?P<vg>\S+)\s+(?P<ev>[A-Z][A-Z_]+)")
VG_EVENT_BAD_RE = re.compile(r"REMOVED|MISSING|FAIL|LOST|CLOSE|STALE")
VG_EVENT_DESC = {
    "PV_REMOVED": "a disk dropped out of the volume group",
    "PV_ADDED": "a disk came back into the volume group",
}

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
    "resource_group_in_error": (Severity.ERROR, "Resource group went into ERROR state"),
    "cluster_ffdc": (Severity.WARNING, "First-failure data capture run after a failure"),
}


# Notification events: they report on another event that is still running
# (config_too_long fires while e.g. rg_move hangs), so they are not put on the
# event stack and do not need a matching COMPLETED line.
NOTIFY_EVENTS = {"config_too_long"}


@dataclass(frozen=True)
class Rule:
    category: str
    severity: Severity
    regex: re.Pattern[str]
    in_trace: bool = False  # also apply to ksh trace lines without --trace


def _r(p: str, cs: bool = False) -> re.Pattern[str]:
    """Compile a rule. Case-insensitive unless cs=True (for upper-case
    keywords such as the ERROR resource-group state)."""
    return re.compile(p, 0 if cs else re.IGNORECASE)


# Ordered: first match wins, so put specific rules first.
RULES: list[Rule] = [
    Rule("config", Severity.WARNING, _r(r"'\.' is in the current path"), True),
    Rule("cluster", Severity.CRITICAL, _r(r"config_too_long|has been running recovery program"), True),
    Rule("cluster", Severity.CRITICAL, _r(r"\bpartition(?:ed)?\b.*\bcluster\b|\bsplit[- ]brain\b|\bdomain merge\b"), True),
    Rule("cluster", Severity.CRITICAL, _r(r"\bhalt(?:ing)? (?:the )?node\b|\bnode (?:will be )?halted\b|\bdead man switch\b|\bDMS\b timeout"), True),
    Rule("resource group", Severity.ERROR, _r(
        r"^\s*[\w.-]+\s+(?:ERROR|OFFLINE due to [\w ]+?)(?:\s+[\w.-]+)?\s*$"
        r"|\b(?:(?i:resource group)|RG)\b.*\bERROR\b"
        r"|\bERROR\b.*\b(?i:resource group)\b"
        r"|\b(?i:state)\b.*\bERROR\b", cs=True), True),
    Rule("resource group", Severity.ERROR, _r(r"\b(?:acquisition|release) of .* failed\b|\bfailed to (?:acquire|release|bring|move)\b"), True),
    Rule("LVM", Severity.ERROR, _r(r"\b05(?:16|11|17)-\d{3,4}\b"), True),  # LVM message IDs
    Rule("LVM", Severity.ERROR, _r(r"\bvaryonvg\b.*\b(?:fail|error|cannot)|unable to vary\s?on|cl_activate_vgs\b.*\b(?:fail|error)|\bvaryon(?:vg)? failed\b"), True),
    Rule("LVM", Severity.ERROR, _r(r"\bquorum\b.*\b(?:lost|not available)\b|\bmissing\b.*\b(?:PV|disk|physical volume)s?\b|\bstale partitions?\b"), True),
    # SRC (startsrc/stopsrc/refresh): 0513-xxx is informational unless the text says otherwise
    Rule("SRC", Severity.ERROR, _r(r"\b0513-\d{3}\b.*(?:\bnot\b|inoperative|timeout|timed out|fail|error|cannot|unable)"), True),
    Rule("disk", Severity.ERROR, _r(r"\breserv(?:e|ation)\b.*\b(?:conflict|fail)|\bSCSI\b.*\b(?:error|reservation)\b|\bdisk fencing\b.*fail"), True),
    Rule("filesystem", Severity.ERROR, _r(r"\bfsck\b.*\b(?:fail|error|unrecoverable)|\bmount\b.*\b(?:fail|error)|\bumount\b.*\b(?:fail|busy|error)|\bdevice busy\b|cl_activate_fs\b.*\b(?:fail|error)|cl_deactivate_fs\b.*\b(?:fail|error)"), True),
    Rule("filesystem", Severity.ERROR, _r(r"\b0506-\d{3}\b|\bfuser\b.*\bkill"), True),
    Rule("filesystem", Severity.ERROR, _r(r"No space left on device|file system (?:is )?full"), True),
    Rule("NFS", Severity.ERROR, _r(r"\bNFS\b.*(?:fail|error|not responding|stale)|exportfs.*(?:fail|error)"), True),
    Rule("network", Severity.ERROR, _r(r"\b(?:ifconfig|route|arp)\b.*(?:fail|error|cannot)|\bIP address\b.*(?:fail|conflict|already in use)|duplicate IP|\bswap_adapter\b.*fail"), True),
    Rule("network", Severity.WARNING, _r(r"\bnetwork\b.*\bdown\b|\binterface\b.*\bdown\b|\badapter\b.*\b(?:down|failed)\b"), False),
    Rule("application", Severity.ERROR, _r(r"\b(?:application|app) (?:server|controller|monitor)\b.*(?:fail|error|could not|unable)|\bstart_server\b.*\b(?:fail|error)|\bstop_server\b.*\b(?:fail|error)|\bmonitor\b.*\bfailure\b"), True),
    Rule("CAA/RSCT", Severity.ERROR, _r(r"\bCAA\b.*(?:fail|error|not running)|\brepository disk\b.*(?:fail|error|lost|unavailable)|\bclcomd\b.*(?:fail|error|not running)|\brsct\b.*(?:fail|error)|\bgrpsvcs\b.*(?:fail|error)"), True),
    Rule("timeout", Severity.ERROR, _r(r"\btimed? ?out\b|\btimeout (?:expired|reached|occurred)\b"), False),
    Rule("permission", Severity.ERROR, _r(r"Permission denied|not owner|Operation not permitted"), False),
    Rule("general", Severity.ERROR, _r(r"!{3,}\s*ERROR\s*!{3,}|^\s*\**\s*ERROR\b|\bERROR\s+\d+\b", cs=True), True),
    Rule("general", Severity.ERROR, _r(r"\berror\s*:|\bFATAL\b|\bfatal error\b|\bcore dump(?:ed)?\b|\bSegmentation fault\b"), True),
    Rule("general", Severity.ERROR, _r(r"\bfailed\b|\bfailure\b|\bunable to\b|\bcannot\b|\bcould not\b|\bcouldn't\b|\babort(?:ed|ing)?\b"), False),
    Rule("general", Severity.WARNING, _r(r"\bnot found\b|No such file or directory|\bnot available\b|\bnot responding\b|\bnot running\b"), False),
    Rule("general", Severity.WARNING, _r(r"!{3,}\s*WARNING\s*!{3,}|^\s*WARNING\b", cs=True), True),
    Rule("general", Severity.WARNING, _r(r"\bwarning\s*:"), True),
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
            r"^Search on:",
            r"^hacmp\.out on the failed nodes\.",  # 2nd line of event_error boilerplate  # event-summary index lines (".All_nonerror_volume_groups...")
            r"^[+:]\S*\]\s+:(?:\s|$)",  # ksh ':' null command = comment in trace
        ]
    ),
    re.IGNORECASE,
)

# Application controller scripts, followed in start_server/stop_server traces
# (always, also without --trace):
#   STOP_SCRIPT=/usr/local/hacmp/hacmp_stop.ksh                  (script path)
#   +RG:stop_server[+123] PATTERN=node1 APP_AP                    (application)
#   +RG:start_server[start_and_monitor_server+60] [ background == background ]
#   +RG:stop_server[+140] /usr/local/hacmp/hacmp_stop.ksh -a APP_AP   (the call)
#   +RG:stop_server[+141] rc=1                                    (its exit status)
#   +RG:start_server[...+98] : exit status of cl_app_startup_monitor is: 1
APP_SCRIPT_RE = re.compile(r"^(?P<kind>START|STOP)_SCRIPT=(?P<path>/\S+)\s*$")
APP_TRACE_RE = re.compile(r"^\+(?P<rg>[^:\s]*):(?P<kind>start|stop)_server\[[^\]]*\]\s+(?P<cmd>.*?)\s*$")
APP_PATTERN_RE = re.compile(r"^PATTERN=\S+\s+(?P<app>\S+)$")
APP_RC_RE = re.compile(r"^(?:rc|RETURN_STATUS|STATUS)=(?P<rc>-?\d+)$")
APP_MON_RE = re.compile(r"^:\s*exit status of cl_app_startup_monitor is:\s*(?P<rc>-?\d+)")
APP_BG_RE = re.compile(r"^\[\[? background == background \]\]?$")


@dataclass
class AppCall:
    kind: str                 # "start" | "stop"
    app: str | None = None
    cmd: str | None = None    # script command line once it has been called
    line: int = 0
    ts: str | None = None
    background: bool = False


# ksh trace of a plain assignment: "+XAP:cl_activate_fs[...:380] comm_failure=''"
TRACE_ASSIGN_RE = re.compile(r"^[+:]\S*\]\s+\w+=\S*\s*$")

_MSG_CMD_RE = re.compile(r"\b(?:cl_log|cl_echo|dspmsg|echo|print|cl_msg|logger)\b")


def _trace_is_message(line: str) -> bool:
    """A trace line that emits a message (cl_log/cl_echo/dspmsg/echo ...)."""
    return bool(_MSG_CMD_RE.search(line))


def _fmt_iso(iso: str) -> str:
    """'2026-10-24T18:42:20' -> 'Oct 24 2026 18:42:20' (same style as hacmp.out)."""
    try:
        return datetime.strptime(iso, "%Y-%m-%dT%H:%M:%S").strftime("%b %d %Y %H:%M:%S")
    except ValueError:
        return iso


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #


@dataclass
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


@dataclass
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


_INT_RE = re.compile(r"-?\d+")


def _parse_rc(args: str) -> tuple[str, int | None]:
    """'nodeA rg1 0' -> ('nodeA rg1', 0). Used only when there is no START line."""
    parts = args.rsplit(None, 1)
    if parts and _INT_RE.fullmatch(parts[-1]):
        return (parts[0] if len(parts) > 1 else ""), int(parts[-1])
    return args, None


def _split_rc(raw: str, start_args: str) -> tuple[str, int | None]:
    """Get the rc by comparing with the START line's args.

    PowerHA 7.x appends the exit status ('rg_move nodeA 3 ACQUIRE 0'); older
    releases don't ('rg_move_acquire nodeA 1'), where a trailing number is an
    argument, not an rc.
    """
    if raw == start_args:
        return start_args, None
    if raw.startswith(start_args):
        rest = raw[len(start_args):].strip()
        if _INT_RE.fullmatch(rest):
            return start_args, int(rest)
    return _parse_rc(raw)


class HacmpParser:
    def __init__(self, *, context: int, trace: bool) -> None:
        self.context = context
        self.trace = trace
        self.events: list[Event] = []
        self.findings: list[Finding] = []
        self._stack: list[Event] = []
        self._file = ""
        self._app_scripts: dict[str, set[str]] = {"start": set(), "stop": set()}
        self._app_calls: dict[tuple[str, str], AppCall] = {}  # (RG, kind) -> state

    # -- helpers -----------------------------------------------------------
    def _current_event(self) -> str | None:
        if not self._stack:
            return None
        e = self._stack[-1]
        return f"{e.name} {e.args}".strip()

    def _find_open(self, name: str, raw_args: str) -> int | None:
        # Prefer the innermost open event whose args match; events with the
        # same name can run in parallel (e.g. start_server for two apps).
        for i in range(len(self._stack) - 1, -1, -1):
            e = self._stack[i]
            if e.name == name and (raw_args == e.args or raw_args.startswith(e.args + " ")
                                   or not e.args):
                return i
        for i in range(len(self._stack) - 1, -1, -1):
            if self._stack[i].name == name:
                return i
        return None

    def _close_event(self, name: str, raw_args: str, rc0: int | None, failed: bool,
                     lineno: int, ts: str | None) -> Event:
        i = self._find_open(name, raw_args)
        if i is not None:
            # Other open events are left alone: siblings may finish in any order.
            ev = self._stack.pop(i)
            _, rc = _split_rc(raw_args, ev.args)
        else:
            args, rc = _parse_rc(raw_args)
            ev = Event(name, args, self._file, lineno, ts, depth=len(self._stack))
            self.events.append(ev)
        if rc0 is not None:
            rc = rc0
        ev.end_line, ev.end_ts, ev.rc = lineno, ts, rc
        ev.failed = failed or (rc is not None and rc != 0)
        return ev

    # -- main loop ---------------------------------------------------------
    def parse(self, path: str) -> None:
        """Parse one file. Open events carry over to the next file until
        end_series() is called (for rotated logs read oldest first)."""
        self._file = path
        last_ts: str | None = None
        before: deque[tuple[int, str]] = deque(maxlen=self.context)
        pending_after: list[tuple[Finding, int]] = []  # finding, lines still needed
        prev_new: list[Finding] = []
        prev_had_ts = True
        recent_trace: deque[tuple[int, Finding]] = deque(maxlen=8)

        with open_log(path) as fh:
            for lineno, raw in enumerate(fh, 1):
                line = raw.rstrip("\n")

                # <LAT> lines duplicate the readable ones: only take their timestamp.
                if line.startswith("<LAT>"):
                    lm = LAT_RE.match(line)
                    if lm and lm["iso"]:
                        last_ts = _fmt_iso(lm["iso"])
                        if not prev_had_ts:
                            for f in prev_new:
                                f.timestamp = last_ts
                    continue

                # Feed "after" context to findings waiting for it
                if pending_after:
                    still: list[tuple[Finding, int]] = []
                    for f, n in pending_after:
                        f.context.append(f"{lineno:>7}  {line}")
                        if n > 1:
                            still.append((f, n - 1))
                    pending_after = still

                tm = TS_RE.match(line)
                if tm:
                    last_ts = _norm_ts(tm)

                new = self._handle_line(line, lineno, last_ts)
                is_trace = bool(TRACE_RE.match(line))
                for f in new:
                    if is_trace:
                        recent_trace.append((lineno, f))
                    else:
                        self._drop_echo_of(f, lineno, recent_trace)
                for f in new:
                    if self.context:
                        f.context = [f"{n:>7}  {l}" for n, l in before]
                        f.context.append(f"{lineno:>7}> {line}")
                        pending_after.append((f, self.context))
                    self.findings.append(f)
                if self.context:
                    before.append((lineno, line))
                prev_new, prev_had_ts = new, bool(tm)

    def _drop_echo_of(self, f: Finding, lineno: int,
                      recent: deque[tuple[int, Finding]]) -> None:
        """A message line is usually preceded by the trace of the command that
        printed it (print 'ERROR: ...' / dspmsg ... / cl_log ...). Keep only
        the printed line."""
        text = TS_RE.sub("", f.message).strip()
        if len(text) < 10:
            return
        for n, tf in list(recent):
            if lineno - n <= 10 and text in tf.message:
                recent.remove((n, tf))
                try:
                    self.findings.remove(tf)
                except ValueError:
                    pass

    def _track_app(self, line: str, lineno: int, ts: str | None) -> Finding | None:
        """Report the controller script and its exit status when a start or
        stop script fails, instead of only PowerHA's generic message."""
        if (m := APP_SCRIPT_RE.match(line)):
            self._app_scripts[m["kind"].lower()].add(m["path"])
            return None
        m = APP_TRACE_RE.match(line)
        if not m:
            return None
        kind, cmd = m["kind"], m["cmd"]
        key = (m["rg"], kind)
        st = self._app_calls.setdefault(key, AppCall(kind))

        if (pm := APP_PATTERN_RE.match(cmd)):
            # PATTERN= precedes every call: start a fresh cycle (keeps background flag
            # only if it was set in this cycle, which comes after PATTERN=)
            st = self._app_calls[key] = AppCall(kind, pm["app"])
        elif APP_BG_RE.match(cmd):
            st.background = True
        elif cmd.split(None, 1)[0] in self._app_scripts[kind]:
            st.cmd, st.line, st.ts = cmd, lineno, ts
        elif st.cmd and (rm := APP_RC_RE.match(cmd)) and not st.background:
            rc = int(rm["rc"])
            call = st.cmd
            self._app_calls.pop(key, None)
            if rc != 0:
                return Finding(Severity.ERROR, "application",
                               f"{kind.capitalize()} script for {st.app or '?'} failed "
                               f"(rc={rc}): {call}",
                               self._file, lineno, ts, self._current_event())
        elif st.cmd and (mm := APP_MON_RE.match(cmd)):
            rc = int(mm["rc"])
            call, bg = st.cmd, st.background
            self._app_calls.pop(key, None)
            if rc != 0:
                how = " (started in background, script exit status not checked)" if bg else ""
                return Finding(Severity.ERROR, "application",
                               f"{st.app or '?'} not running after start script "
                               f"(startup monitor rc={rc}){how}: {call}",
                               self._file, lineno, ts, self._current_event())
        return None

    def end_series(self) -> None:
        """Report events still open after the last file of a log series."""
        for ev in self._stack:
            self.findings.append(Finding(
                Severity.WARNING, "event",
                f"Event never completed: {ev.name} {ev.args}".strip()
                + " (hung, node crashed/halted, or log rotated)",
                ev.file, ev.start_line, ev.start_ts, None))
        self._stack.clear()

    def _handle_line(self, line: str, lineno: int, ts: str | None) -> list[Finding]:
        out: list[Finding] = []
        is_trace = bool(TRACE_RE.match(line))

        # ---- cluster event bookkeeping ----------------------------------
        if "EVENT " in line and not is_trace:
            if (m := EVENT_START_RE.search(line)):
                parent = self._current_event()
                ev = Event(m["name"], m["args"], self._file, lineno, ts, depth=len(self._stack))
                self.events.append(ev)
                if ev.name in NOTIFY_EVENTS:
                    ev.end_line = lineno  # not tracked as running
                else:
                    self._stack.append(ev)
                if (pe := PROBLEM_EVENTS.get(ev.name)):
                    sev, desc = pe
                    out.append(Finding(sev, "event", f"{desc}: {ev.name} {ev.args}".strip(),
                                       self._file, lineno, ts, parent))
                return out

            if (m := EVENT_FAIL_RE.search(line)):
                rc0 = int(m["rc0"]) if m["rc0"] is not None else None
                ev = self._close_event(m["name"], m["args"], rc0, True, lineno, ts)
                out.append(Finding(Severity.CRITICAL, "event",
                                   f"EVENT FAILED: {ev.name} {ev.args}".strip() + f" (rc={ev.rc})",
                                   self._file, lineno, ts, self._current_event()))
                return out

            if (m := EVENT_DONE_RE.search(line)):
                if m["name"] in NOTIFY_EVENTS:
                    return out
                ev = self._close_event(m["name"], m["args"], None, False, lineno, ts)
                if ev.failed:
                    out.append(Finding(Severity.CRITICAL, "event",
                                       f"Event completed with non-zero exit status: "
                                       f"{ev.name} {ev.args}".strip() + f" (rc={ev.rc})",
                                       self._file, lineno, ts, self._current_event()))
                return out

        # ---- application controller start/stop scripts -------------------
        if (f := self._track_app(line, lineno, ts)) is not None:
            out.append(f)
            return out

        # ---- error / warning lines --------------------------------------
        if not line.strip() or NOISE_RE.search(line):
            return out

        if not is_trace and (m := VG_EVENT_RE.search(line)):
            ev_type = m["ev"]
            sev = Severity.ERROR if VG_EVENT_BAD_RE.search(ev_type) else Severity.WARNING
            desc = VG_EVENT_DESC.get(ev_type)
            msg = f"volumeGroupEvent {m['vg']} {ev_type}" + (f" - {desc}" if desc else "")
            out.append(Finding(sev, "LVM", msg, self._file, lineno, ts, self._current_event()))
            return out

        if is_trace:
            if self.trace and (m := TRACE_RC_RE.search(line)):
                out.append(Finding(Severity.WARNING, "return code",
                                   f"Non-zero return code (rc={m['rc']}): {line.strip()}",
                                   self._file, lineno, ts, self._current_event()))
                return out
            if not self.trace and not _trace_is_message(line):
                return out  # without --trace only look at trace lines that print a message
            if TRACE_ASSIGN_RE.match(line):
                return out  # plain variable assignment (failfile=..., comm_failure='')

        for rule in RULES:
            if is_trace and not (self.trace or rule.in_trace):
                continue
            if rule.regex.search(line):
                out.append(Finding(rule.severity, rule.category, line.strip(),
                                   self._file, lineno, ts, self._current_event()))
                break
        return out


# --------------------------------------------------------------------------- #
# File ordering
# --------------------------------------------------------------------------- #

_ROT_RE = re.compile(r"^(?P<base>.*?)(?:\.(?P<n>\d{1,3}))?$")


def order_files(paths: list[str], keep_order: bool) -> list[list[str]]:
    """Group rotated copies of the same log (x, x.1, x.2 ...) and order each
    group oldest first: x.2, x.1, x. Groups keep the order they were given in."""
    if keep_order:
        return [paths]
    groups: dict[str, list[tuple[int, str]]] = {}
    for p in paths:
        m = _ROT_RE.match(p)
        base = m["base"] if m and p != "-" else p
        n = int(m["n"]) if m and m["n"] and p != "-" else 0
        groups.setdefault(base, []).append((n, p))
    return [[p for _, p in sorted(g, key=lambda t: -t[0])] for g in groups.values()]


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
                      "NOT COMPLETED" if e.end_line is None else
                      "OK" if e.rc in (0, None) else f"rc={e.rc}")
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
    ap.add_argument("--keep-order", action="store_true",
                    help="analyse files in the order given (no rotation sorting)")
    ap.add_argument("--no-color", action="store_true", help="disable colours")
    args = ap.parse_args(argv)

    parser = HacmpParser(context=max(0, args.context), trace=args.trace)
    files_ok: list[str] = []
    for series in order_files(args.files, args.keep_order):
        for path in series:
            try:
                parser.parse(path)
                files_ok.append(path)
            except OSError as exc:
                print(f"error: cannot read {path}: {exc}", file=sys.stderr)
        parser.end_series()
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
