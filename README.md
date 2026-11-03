# Python Security Log Analyzer

A small, dependency-free command-line tool that reads authentication logs, finds failed logins, detects **brute-force bursts** with a sliding time window, and gives every source IP a **risk level** and a **recommended action**. Detections are mapped to MITRE ATT&CK **T1110 – Brute Force**.

Built as a Blue Team learning project: the goal is to do by hand what a SIEM rule does, so I understand how detection logic actually works.

## Features

- Parses two log formats: a custom `YYYY-MM-DD HH:MM:SS ... FAILED ... <ip>` format and OpenSSH `auth.log` (`Failed password` lines)
- Counts failed logins per IP and tracks first/last seen and the usernames each IP tried
- Detects brute-force bursts with a **sliding window** (default: 5 failures within 5 minutes), configurable from the command line
- Classifies IPs as `PRIVATE` or `PUBLIC`
- Assigns a risk level (`LOW` / `MEDIUM` / `HIGH`) and a recommended action (`ALLOW` / `INVESTIGATE` / `BLOCK`)
- Writes a text report and, optionally, a JSON report
- Handles empty logs, out-of-order timestamps and malformed lines without crashing
- 19 unit tests (`unittest`, standard library only)

## Quick start

Requires Python 3.8+ and nothing else.

```bash
git clone https://github.com/<your-username>/<repo-name>.git
cd <repo-name>

# custom log format
python main.py sample_logs/security.log

# OpenSSH auth.log (syslog timestamps have no year, so pass one)
python main.py sample_logs/auth.log --year 2026
```

With no arguments the tool analyzes `security.log` in the current folder.

### Options

| Option | Default | Meaning |
| --- | --- | --- |
| `logfile` | `security.log` | Log file to analyze |
| `--threshold N` | `5` | Failed logins that count as a brute-force burst |
| `--window MIN` | `5` | Window (minutes) for the burst rule |
| `--medium N` | `3` | Total failures that make an IP `MEDIUM` risk |
| `--high N` | `10` | Total failures that make an IP `HIGH` risk |
| `--year YYYY` | current year | Year to assume for syslog timestamps |
| `--output PATH` | `security_report.txt` | Text report path |
| `--no-file` | off | Print only, do not write the text report |
| `--json PATH` | off | Also write results as JSON |

## Supported log formats

```text
# custom format (the IP can be anywhere after the timestamp)
2026-11-02 09:02:10 WARNING Login FAILED for admin from 203.0.113.45

# OpenSSH auth.log
Nov  2 07:41:19 web01 sshd[2201]: Failed password for root from 203.0.113.45 port 40001 ssh2
```

Only failed logins are analyzed. Successful logins, `Invalid user` notices (they duplicate the `Failed password` line) and other messages are ignored. A line that looks like a failed login but cannot be parsed is counted as *unparsed* instead of stopping the run.

## How it works

1. Each line is parsed into a failed-login event (timestamp, IP, username).
2. Events are sorted by time, because logs are not always in order.
3. For every IP the tool keeps a queue of recent failures. Old entries leave the queue when they fall outside the window. If the queue reaches the threshold, that is one brute-force burst.
4. Risk is assigned per IP:

| Condition | Risk | Recommended action |
| --- | --- | --- |
| Brute-force burst **or** total failures >= `--high` | `HIGH` | `BLOCK` |
| Total failures >= `--medium` | `MEDIUM` | `INVESTIGATE` |
| Otherwise | `LOW` | `ALLOW` |

The "action" is a recommendation printed in the report. The tool does not change firewall rules.

## Example output

`python main.py sample_logs/auth.log --year 2026` (shortened):

```text
SECURITY LOG ANALYSIS REPORT
============================
Lines read      : 27
Failed logins   : 16
Detection rule  : >= 5 failed logins from one IP within 5 min (T1110 - Brute Force)

SUMMARY
-------
Most active IP        : 203.0.113.45 (12 failures)
Brute-force IPs       : 1
Recommended to block  : 1
Top targeted usernames: deploy (4), root (4), admin (3), oracle (1), test (1)

IP ANALYSIS
-----------
203.0.113.45
    Scope           : PUBLIC
    Failed attempts : 12
    Peak in window  : 12 within 5 min
    Brute-force     : YES - 1 burst(s), first at 2026-11-02 07:41:49 [T1110 - Brute Force]
    Usernames tried : root (4), admin (3), oracle (1), test (1), ubuntu (1)
    Risk            : HIGH
    Decision        : BLOCK

BLOCK LIST
----------
203.0.113.45 -> BLOCK
```

Full reports are in [`sample_output/`](sample_output/). The sample logs use IPs from the reserved documentation ranges (RFC 5737), so they do not point at real hosts.

## Project structure

```text
.
├── main.py                 # command-line interface
├── log_analyzer.py         # parsing, detection, risk scoring, reports
├── test_log_analyzer.py    # unit tests
├── sample_logs/
│   ├── security.log        # custom format example
│   └── auth.log            # OpenSSH example
├── sample_output/          # reports generated from the sample logs
├── README.md
└── .gitignore
```

## Running the tests

```bash
python -m unittest -v
```

## Limitations and ideas

- Syslog timestamps have no year, so the year is assumed (`--year`). Logs that span New Year can be ordered wrongly.
- Only failed password logins are detected. Failed public-key logins, Windows Event Logs and web server logs are not supported yet.
- It analyzes a finished file; it does not follow a live log.
- Possible next steps: Windows Event ID 4625 support, a `tail -f` live mode, allow-lists for trusted IPs, GeoIP enrichment, and exporting a ready-made firewall block list.

## What I learned

Turning a simple counter into a sliding-window detection, thinking about false positives (a user mistyping a password twice is not an attack), and writing tests for edge cases such as empty logs and out-of-order events.
