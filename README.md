# hacmp_analyze

Scan PowerHA SystemMirror (HACMP) `hacmp.out` logs for errors and problems and
print a readable, categorised report.

`hacmp.out` is huge and noisy — thousands of lines of ksh `set -x` trace output
per cluster event. `hacmp_analyze.py` pulls out what matters: failed events,
hung events, problem events and real error messages, each with its file, line
number, timestamp and the cluster event it happened in.

## Requirements

- Python 3.10 or newer (the shebang points to `python3.12`)
- No third-party packages — standard library only

The script is a single file; copy it to the cluster node or run it on a copy
of the logs on any machine.

## Usage

```sh
hacmp_analyze.py [FILE ...] [options]
```

- With no `FILE`, the default `/var/hacmp/log/hacmp.out` is read.
- Several files may be given, e.g. rotated logs: `hacmp.out hacmp.out.1 hacmp.out.2`.
- Use `-` to read from stdin.

### Options

| Option | Description |
|---|---|
| `-C N`, `--context N` | Show N lines of context before and after each finding (default 0) |
| `--trace` | Also scan ksh `set -x` trace lines and report non-zero `RC=`/`rc=` values (more findings, more noise) |
| `--min-severity S` | Lowest severity to report: `CRITICAL`, `ERROR` or `WARNING` (default `WARNING`) |
| `--no-dedup` | Print every matching line instead of grouping repeated messages |
| `--no-color` | Disable ANSI colours (colours are also off when stdout is not a terminal) |

### Examples

```sh
# Analyse the live log on a cluster node
./hacmp_analyze.py

# Current and rotated logs, errors only, 3 lines of context
./hacmp_analyze.py /var/hacmp/log/hacmp.out* --min-severity ERROR -C 3

# Logs collected from another node (e.g. from a snap), piped in
gzip -dc hacmp.out.gz | ./hacmp_analyze.py - --no-color > report.txt

# Deep dive including trace output
./hacmp_analyze.py hacmp.out --trace -C 5 | less -R
```

## What it finds

**Cluster events**
- Events that logged `EVENT FAILED`
- Events that ended with `EVENT COMPLETED` but a non-zero exit status
- Events that were started but never completed (hung, node crashed/halted, or log rotated)
- Problem events whose occurrence alone is worth noting, e.g. `config_too_long`,
  `event_error`, `node_down`, `site_down`, `network_down`, `fail_interface`,
  `swap_adapter`, `server_down`, `split_merge_prompt`, `cluster_split`

**Error and warning lines**, grouped by category:

| Category | Examples |
|---|---|
| cluster | `config_too_long`, split brain / partitioned cluster, node halt, dead man switch |
| resource group | RG in `ERROR` state, failed acquisition/release |
| LVM | AIX LVM message IDs (`0516-xxx`, `0511-`, `0513-`, `0517-`), `varyonvg` failures, lost quorum, missing PVs, stale partitions |
| disk | SCSI reservation conflicts, disk fencing failures |
| filesystem | `fsck`/`mount`/`umount` failures, device busy, `0506-xxx`, file system full |
| NFS | NFS / `exportfs` errors, stale handles |
| network | `ifconfig`/`route`/`arp` failures, duplicate IP, interface/adapter down |
| application | Application controller start/stop/monitor failures |
| CAA/RSCT | CAA, repository disk, `clcomd`, RSCT, `grpsvcs` errors |
| timeout, permission, general | Timeouts, `Permission denied`, `ERROR:`, `failed`, `cannot`, `FATAL`, core dumps, `WARNING:` … |

Known noise such as `errors=0`, `no errors`, `failure_notification` and
commented-out script lines is filtered out.

### Trace lines

By default, ksh trace lines (`+rg1:cl_activate_vgs[256] ...`,
`:node_up[123] ...`) are only checked when they emit a message
(`cl_log`, `cl_echo`, `dspmsg`, `echo`, …) and only against high-signal rules.
With `--trace` all rules apply to trace lines and non-zero return codes
(`RC=1`, `status=2`, …) are reported as well.

## Output

The report has three parts: a summary, a timeline of top-level events (nested
events are shown only when they failed), and the findings grouped by category,
most severe first. Repeated messages (identical apart from numbers) are folded
into one entry with a count and the last line number.

```
==============================================================================
 PowerHA hacmp.out analysis
==============================================================================
 Files analysed : sample.out
 Events found   : 3
 Failed events  : 1
 Findings       : CRITICAL=2, ERROR=1, WARNING=1

-- Event timeline (top-level events, failures marked) -----------------------
 Mar 12 10:15:01       OK            node_up nodeA  [sample.out:1]
 Mar 12 10:15:02       FAILED          acquire_service_addr   [sample.out:2]
 Mar 12 10:20:00       NOT COMPLETED config_too_long 360 TE_RG_MOVE  [sample.out:6]

-- Problems found ------------------------------------------------------------

[EVENT]  (3 occurrence(s))
  CRITICAL sample.out:4  Mar 12 10:15:09
           EVENT FAILED: acquire_service_addr (rc=1)
           during event: node_up nodeA
  CRITICAL sample.out:6  Mar 12 10:20:00
           Event processing hung / took too long (config_too_long): config_too_long 360 TE_RG_MOVE
           during event: config_too_long 360 TE_RG_MOVE
  WARNING  sample.out:6  Mar 12 10:20:00
           Event never completed: config_too_long 360 TE_RG_MOVE (hung, node crashed/halted, or log rotated)

[LVM]  (1 occurrence(s))
  ERROR    sample.out:3  Mar 12 10:15:02
           0516-013 varyonvg: The volume group cannot be varied on because there are no good copies of the descriptor area.
           during event: acquire_service_addr
```

## Exit status

| Code | Meaning |
|---|---|
| 0 | Nothing found |
| 1 | Warnings only |
| 2 | Errors or critical findings |
| 3 | None of the given files could be read |

This makes the script usable from cron or monitoring checks, e.g.
`hacmp_analyze.py --min-severity ERROR --no-color >/dev/null || alert`.

## Supported log formats

Timestamps from different PowerHA versions are recognised:

```
Mar 12 10:15:01 EVENT START: ...
Mar 12 2024 10:15:01 EVENT START: ...
Tue Mar 12 10:15:01 CET 2024
```

`EVENT FAILED` is parsed both as `EVENT FAILED: 1: node_up nodeA 1` and
`EVENT FAILED: node_up nodeA 1`. Files are read as UTF-8 with invalid bytes
replaced, so binary garbage in the log does not stop the scan.

## Extending

Detection rules live at the top of `hacmp_analyze.py`:

- `PROBLEM_EVENTS` — event names reported whenever they start, with severity and description
- `RULES` — ordered regex rules (first match wins; put specific rules first).
  `in_trace=True` lets a rule match message-emitting trace lines without `--trace`.
- `NOISE_RE` — patterns for lines that look like errors but are not
