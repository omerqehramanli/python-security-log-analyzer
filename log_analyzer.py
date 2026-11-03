"""Core logic for the Security Log Analyzer.

Parses authentication logs, extracts failed logins, detects brute-force
bursts with a sliding time window and assigns a risk level and a recommended
action to every source IP address.

Only the Python standard library is used.
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Deque, Dict, Iterable, List, Optional

MITRE_TECHNIQUE = "T1110 - Brute Force"

DEFAULT_THRESHOLD = 5  # failed logins from one IP ...
DEFAULT_WINDOW_MINUTES = 5  # ... inside this many minutes = brute-force burst
DEFAULT_MEDIUM = 3  # total failures that make an IP MEDIUM risk
DEFAULT_HIGH = 10  # total failures that make an IP HIGH risk

CUSTOM_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"

# Linux sshd syslog line, e.g.
# Nov  2 10:15:32 server sshd[1234]: Failed password for invalid user admin from 203.0.113.45 port 52144 ssh2
SSH_FAILED_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+sshd(?:\[\d+\])?:\s+Failed password for (?:invalid user )?(?P<user>\S+)\s+"
    r"from\s+(?P<ip>\S+)\s+port\s+\d+"
)
SYSLOG_PREFIX_RE = re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s")
CUSTOM_USER_RE = re.compile(
    r"(?:\buser[=:]\s*|\bfor\s+(?:invalid user\s+)?)(?P<user>[^\s,;]+)", re.IGNORECASE
)

# Python marks the TEST-NET documentation ranges as "private". They stand in for
# internet addresses in examples, so we treat them as public.
_DOCUMENTATION_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]


class LogParseError(ValueError):
    """A line looks like a failed login but could not be parsed."""


@dataclass(frozen=True)
class FailedLogin:
    timestamp: datetime
    ip: str
    username: Optional[str] = None


@dataclass
class IPStats:
    ip: str
    failures: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    usernames: Counter = field(default_factory=Counter)
    bruteforce_bursts: int = 0
    first_bruteforce_at: Optional[datetime] = None
    peak_in_window: int = 0
    risk: str = "LOW"
    decision: str = "ALLOW"

    @property
    def is_private(self) -> bool:
        return is_private_address(self.ip)

    @property
    def scope(self) -> str:
        return "PRIVATE" if self.is_private else "PUBLIC"

    @property
    def is_bruteforce(self) -> bool:
        return self.bruteforce_bursts > 0


@dataclass
class AnalysisResult:
    total_lines: int
    failed_logins: int
    malformed_lines: int
    ip_stats: List[IPStats]
    usernames: Counter
    threshold: int
    window_minutes: int
    medium_threshold: int
    high_threshold: int
    first_event: Optional[datetime] = None
    last_event: Optional[datetime] = None

    @property
    def most_active(self) -> Optional[IPStats]:
        return self.ip_stats[0] if self.ip_stats else None

    @property
    def bruteforce_ips(self) -> List[IPStats]:
        return [s for s in self.ip_stats if s.is_bruteforce]

    @property
    def blocked_ips(self) -> List[IPStats]:
        return [s for s in self.ip_stats if s.decision == "BLOCK"]


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #
def is_private_address(ip: str) -> bool:
    address = ipaddress.ip_address(ip)
    if any(address in network for network in _DOCUMENTATION_NETWORKS if address.version == 4):
        return False
    return address.is_private


def _valid_ip(candidate: str) -> Optional[str]:
    """Return the normalised IP if `candidate` is one, else None."""
    token = candidate.strip(",;()[]")
    if "=" in token:
        token = token.split("=", 1)[1]
    try:
        return str(ipaddress.ip_address(token))
    except ValueError:
        return None


def _parse_ssh(match: "re.Match[str]", year: int, line: str) -> FailedLogin:
    stamp = f"{year} {match['month']} {match['day']} {match['time']}"
    try:
        timestamp = datetime.strptime(stamp, "%Y %b %d %H:%M:%S")
    except ValueError as exc:
        raise LogParseError(f"invalid timestamp: {line!r}") from exc
    ip = _valid_ip(match["ip"])
    if ip is None:
        raise LogParseError(f"invalid IP address: {line!r}")
    return FailedLogin(timestamp, ip, match["user"])


def _parse_custom(line: str) -> FailedLogin:
    tokens = line.split()
    if len(tokens) < 3:
        raise LogParseError(f"too few fields: {line!r}")
    try:
        timestamp = datetime.strptime(f"{tokens[0]} {tokens[1]}", CUSTOM_TIMESTAMP_FORMAT)
    except ValueError as exc:
        raise LogParseError(f"invalid timestamp: {line!r}") from exc
    ip = next((found for found in map(_valid_ip, tokens[2:]) if found), None)
    if ip is None:
        raise LogParseError(f"no IP address found: {line!r}")
    user_match = CUSTOM_USER_RE.search(line)
    return FailedLogin(timestamp, ip, user_match["user"] if user_match else None)


def parse_line(line: str, year: Optional[int] = None) -> Optional[FailedLogin]:
    """Parse one log line.

    Returns a FailedLogin for failed-login lines, None for every other line and
    raises LogParseError for failed-login lines that cannot be understood.

    Supported formats:
      * custom:  "2026-11-02 10:15:01 ... FAILED ... <ip> ..."
      * OpenSSH: "Nov  2 10:15:32 host sshd[1]: Failed password for <user> from <ip> port N ssh2"
        (syslog has no year, so `year` is assumed; default is the current year)
    """
    line = line.strip()
    if not line:
        return None
    year = year or datetime.now().year

    ssh_match = SSH_FAILED_RE.match(line)
    if ssh_match:
        return _parse_ssh(ssh_match, year, line)
    if SYSLOG_PREFIX_RE.match(line):
        return None  # some other syslog message, not a failed password
    if "FAILED" in line.upper():
        return _parse_custom(line)
    return None


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #
def assess_risk(
    stats: IPStats, medium_threshold: int = DEFAULT_MEDIUM, high_threshold: int = DEFAULT_HIGH
) -> None:
    """Set `risk` and the recommended `decision` on an IPStats object."""
    if stats.is_bruteforce or stats.failures >= high_threshold:
        stats.risk, stats.decision = "HIGH", "BLOCK"
    elif stats.failures >= medium_threshold:
        stats.risk, stats.decision = "MEDIUM", "INVESTIGATE"
    else:
        stats.risk, stats.decision = "LOW", "ALLOW"


def analyze(
    lines: Iterable[str],
    year: Optional[int] = None,
    threshold: int = DEFAULT_THRESHOLD,
    window_minutes: int = DEFAULT_WINDOW_MINUTES,
    medium_threshold: int = DEFAULT_MEDIUM,
    high_threshold: int = DEFAULT_HIGH,
) -> AnalysisResult:
    """Analyze log lines and return per-IP statistics."""
    if threshold < 1:
        raise ValueError("threshold must be at least 1")
    if window_minutes <= 0:
        raise ValueError("window must be greater than 0 minutes")
    if medium_threshold > high_threshold:
        raise ValueError("medium threshold cannot be higher than the high threshold")

    events: List[FailedLogin] = []
    total_lines = malformed = 0
    for line in lines:
        total_lines += 1
        try:
            event = parse_line(line, year)
        except LogParseError:
            malformed += 1
            continue
        if event:
            events.append(event)

    events.sort(key=lambda e: e.timestamp)  # logs are not always in order
    window = timedelta(minutes=window_minutes)

    stats_by_ip: Dict[str, IPStats] = {}
    recent: Dict[str, Deque[datetime]] = {}
    in_burst: Dict[str, bool] = {}
    usernames: Counter = Counter()

    for event in events:
        stats = stats_by_ip.setdefault(event.ip, IPStats(ip=event.ip))
        stats.failures += 1
        if stats.first_seen is None:
            stats.first_seen = event.timestamp
        stats.last_seen = event.timestamp
        if event.username:
            stats.usernames[event.username] += 1
            usernames[event.username] += 1

        # Sliding window: keep only failures from the last `window_minutes`.
        queue = recent.setdefault(event.ip, deque())
        queue.append(event.timestamp)
        while event.timestamp - queue[0] > window:
            queue.popleft()
        stats.peak_in_window = max(stats.peak_in_window, len(queue))

        if len(queue) >= threshold:
            if not in_burst.get(event.ip):
                in_burst[event.ip] = True
                stats.bruteforce_bursts += 1
                if stats.first_bruteforce_at is None:
                    stats.first_bruteforce_at = event.timestamp
        else:
            in_burst[event.ip] = False

    ordered = sorted(stats_by_ip.values(), key=lambda s: (-s.failures, s.ip))
    for stats in ordered:
        assess_risk(stats, medium_threshold, high_threshold)

    return AnalysisResult(
        total_lines=total_lines,
        failed_logins=len(events),
        malformed_lines=malformed,
        ip_stats=ordered,
        usernames=usernames,
        threshold=threshold,
        window_minutes=window_minutes,
        medium_threshold=medium_threshold,
        high_threshold=high_threshold,
        first_event=events[0].timestamp if events else None,
        last_event=events[-1].timestamp if events else None,
    )


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
def _fmt(moment: Optional[datetime]) -> str:
    return moment.strftime("%Y-%m-%d %H:%M:%S") if moment else "-"


def _top(counter: Counter, limit: int = 5) -> str:
    return ", ".join(f"{name} ({count})" for name, count in counter.most_common(limit)) or "-"


def render_text(result: AnalysisResult, generated_at: Optional[datetime] = None) -> str:
    generated_at = generated_at or datetime.now()
    out: List[str] = [
        "SECURITY LOG ANALYSIS REPORT",
        "============================",
        f"Generated       : {_fmt(generated_at)}",
        f"Lines read      : {result.total_lines}",
        f"Failed logins   : {result.failed_logins}",
        f"Unparsed lines  : {result.malformed_lines}",
        f"Time range      : {_fmt(result.first_event)} -> {_fmt(result.last_event)}",
        f"Detection rule  : >= {result.threshold} failed logins from one IP within "
        f"{result.window_minutes} min ({MITRE_TECHNIQUE})",
        f"Risk rules      : HIGH = brute-force burst or >= {result.high_threshold} failures; "
        f"MEDIUM = >= {result.medium_threshold} failures; otherwise LOW",
        "",
    ]

    if not result.ip_stats:
        out.append("No failed login events found.")
        return "\n".join(out) + "\n"

    top = result.most_active
    out += [
        "SUMMARY",
        "-------",
        f"Most active IP        : {top.ip} ({top.failures} failures)",
        f"Brute-force IPs       : {len(result.bruteforce_ips)}",
        f"Recommended to block  : {len(result.blocked_ips)}",
        f"Top targeted usernames: {_top(result.usernames)}",
        "",
        "IP ANALYSIS",
        "-----------",
    ]
    for stats in result.ip_stats:
        if stats.is_bruteforce:
            brute = (
                f"YES - {stats.bruteforce_bursts} burst(s), first at "
                f"{_fmt(stats.first_bruteforce_at)} [{MITRE_TECHNIQUE}]"
            )
        else:
            brute = "no"
        out += [
            stats.ip,
            f"    Scope           : {stats.scope}",
            f"    Failed attempts : {stats.failures}",
            f"    First / last    : {_fmt(stats.first_seen)} -> {_fmt(stats.last_seen)}",
            f"    Peak in window  : {stats.peak_in_window} within {result.window_minutes} min",
            f"    Brute-force     : {brute}",
            f"    Usernames tried : {_top(stats.usernames)}",
            f"    Risk            : {stats.risk}",
            f"    Decision        : {stats.decision}",
            "",
        ]

    out += ["BLOCK LIST", "----------"]
    if result.blocked_ips:
        out += [f"{stats.ip} -> BLOCK" for stats in result.blocked_ips]
    else:
        out.append("No IPs recommended for blocking")
    return "\n".join(out) + "\n"


def to_dict(result: AnalysisResult) -> dict:
    """JSON-friendly version of the analysis result."""
    return {
        "summary": {
            "lines_read": result.total_lines,
            "failed_logins": result.failed_logins,
            "unparsed_lines": result.malformed_lines,
            "first_event": result.first_event.isoformat() if result.first_event else None,
            "last_event": result.last_event.isoformat() if result.last_event else None,
            "brute_force_ips": [s.ip for s in result.bruteforce_ips],
            "block_list": [s.ip for s in result.blocked_ips],
            "top_usernames": dict(result.usernames.most_common(10)),
        },
        "rules": {
            "brute_force": f">= {result.threshold} failures within {result.window_minutes} minutes",
            "mitre_attack": MITRE_TECHNIQUE,
            "medium_threshold": result.medium_threshold,
            "high_threshold": result.high_threshold,
        },
        "ips": [
            {
                "ip": s.ip,
                "scope": s.scope,
                "failed_attempts": s.failures,
                "first_seen": s.first_seen.isoformat() if s.first_seen else None,
                "last_seen": s.last_seen.isoformat() if s.last_seen else None,
                "peak_in_window": s.peak_in_window,
                "brute_force_bursts": s.bruteforce_bursts,
                "usernames": dict(s.usernames.most_common(10)),
                "risk": s.risk,
                "decision": s.decision,
            }
            for s in result.ip_stats
        ],
    }
