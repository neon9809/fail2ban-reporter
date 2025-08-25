import os
import re
import time
import smtplib
import ssl
import json
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from typing import List, Tuple, Dict, Counter
from collections import Counter as _Counter

try:
    import requests
except Exception:
    requests = None

LOG_PATH = os.getenv("LOG_PATH", "/var/log/fail2ban.log")
INTERVAL_STR = os.getenv("INTERVAL", "1h")
MAIL_PROVIDER = os.getenv("MAIL_PROVIDER", "smtp").lower()
MAIL_TO = [x.strip() for x in os.getenv("MAIL_TO", "").split(",") if x.strip()]
SUBJECT_PREFIX = os.getenv("SUBJECT_PREFIX", "[Fail2Ban]")
TOP_N = int(os.getenv("TOP_N", "5"))

# SMTP config
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
SMTP_TLS = os.getenv("SMTP_TLS", "true").lower() == "true"
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USER or "no-reply@example.com")

# Resend config
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
RESEND_FROM = os.getenv("RESEND_FROM", "")

# Timezone handling (optional TZ env)
if tz := os.getenv("TZ"):
    os.environ["TZ"] = tz
    try:
        time.tzset()  # type: ignore[attr-defined]
    except Exception:
        pass

# Regexes
TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")
BAN_RE = re.compile(r"\bBan\s+([^\s]+)")
UNBAN_RE = re.compile(r"\bUnban\s+([^\s]+)")
FOUND_RE = re.compile(r"\bFound\b")

INTERVAL_RE = re.compile(r"^(?:(?P<h>\d+)h)?(?:(?P<m>\d+)m)?(?:(?P<s>\d+)s)?$")


def parse_interval(s: str) -> timedelta:
    m = INTERVAL_RE.match(s.strip())
    if not m or (not m.group("h") and not m.group("m") and not m.group("s")):
        raise ValueError(f"Invalid INTERVAL: '{s}'. Use forms like '3h5m', '15m', '45s'.")
    h = int(m.group("h") or 0)
    m_ = int(m.group("m") or 0)
    s_ = int(m.group("s") or 0)
    return timedelta(hours=h, minutes=m_, seconds=s_)


def parse_log_window(path: str, start: datetime, end: datetime) -> Tuple[List[str], List[str], List[str], int]:
    """
    Returns: ban_ips_list, unban_ips_list, found_ips_list, fails_count within [start, end].
    found_ips_list contains one entry per 'Found' line with the offending IP.
    """
    ban_ips: List[str] = []
    unban_ips: List[str] = []
    found_ips: List[str] = []
    fails = 0

    if not os.path.exists(path):
        return ban_ips, unban_ips, found_ips, fails

    with open(path, "r", errors="ignore") as f:
        for line in f:
            ts_match = TS_RE.match(line)
            if not ts_match:
                continue
            ts_str = ts_match.group(1)
            try:
                ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                try:
                    ts = datetime.fromisoformat(ts_str)
                except Exception:
                    continue

            if not (start <= ts <= end):
                continue

            if (m := BAN_RE.search(line)):
                ip = m.group(1)
                ban_ips.append(ip)
            elif (m := UNBAN_RE.search(line)):
                ip = m.group(1)
                unban_ips.append(ip)
            elif FOUND_RE.search(line):
                # extract IP after 'Found' keyword if present
                parts = line.split()
                for idx, w in enumerate(parts):
                    if w == "Found" and idx + 1 < len(parts):
                        found_ips.append(parts[idx + 1])
                        break
                fails += 1

    return ban_ips, unban_ips, found_ips, fails


def build_report(start: datetime, end: datetime,
                 ban_ips: List[str],
                 unban_ips: List[str],
                 found_ips: List[str],
                 fails: int,
                 top_n: int) -> str:
    uniq_ban = sorted(set(ban_ips))
    uniq_unban = sorted(set(unban_ips))
    # Top N IPs by Found occurrences
    top_fails = _Counter(found_ips).most_common(top_n)

    lines = []
    lines.append(f"时间窗口: {start} ~ {end}")
    lines.append("")
    lines.append(f"Ban IP 数量: {len(uniq_ban)}")
    lines.append(f"Unban IP 数量: {len(uniq_unban)}")
    lines.append(f"失败尝试次数(Found): {fails}")
    lines.append("")

    lines.append("Ban IP list:")
    if uniq_ban:
        for ip in uniq_ban:
            lines.append(f"  - {ip}")
    else:
        lines.append("  - (无)")
    lines.append("")

    lines.append("Unban IP list:")
    if uniq_unban:
        for ip in uniq_unban:
            lines.append(f"  - {ip}")
    else:
        lines.append("  - (无)")
    lines.append("")

    if top_fails:
        lines.append(f"失败尝试次数最多的{top_n}个IP地址:")
        for ip, cnt in top_fails:
            lines.append(f"  - {ip} (x{cnt})")
        lines.append("")

    return "\n".join(lines)


def send_mail_smtp(subject: str, body: str):
    if not MAIL_TO:
        print("[WARN] MAIL_TO not set; skip sending.")
        return
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = ", ".join(MAIL_TO)

    if SMTP_PORT == 465:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context) as server:
            if SMTP_USER:
                server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_FROM, MAIL_TO, msg.as_string())
    else:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            if SMTP_TLS:
                server.starttls(context=ssl.create_default_context())
            if SMTP_USER:
                server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_FROM, MAIL_TO, msg.as_string())


def send_mail_resend(subject: str, body: str):
    if not requests:
        raise RuntimeError("requests not available; cannot use Resend.")
    if not MAIL_TO:
        print("[WARN] MAIL_TO not set; skip sending.")
        return
    if not RESEND_API_KEY or not RESEND_FROM:
        raise RuntimeError("RESEND_API_KEY / RESEND_FROM not set.")
    url = "https://api.resend.com/emails"
    payload = {
        "from": RESEND_FROM,
        "to": MAIL_TO,
        "subject": subject,
        "text": body,
    }
    headers = {
        "Authorization": f"Bearer {RESEND_API_KEY}",
        "Content-Type": "application/json",
    }
    resp = requests.post(url, headers=headers, data=json.dumps(payload), timeout=20)
    if resp.status_code >= 300:
        raise RuntimeError(f"Resend API error: {resp.status_code} {resp.text}")


def run_once(now: datetime, interval: timedelta):
    start = now - interval
    ban_ips, unban_ips, found_ips, fails = parse_log_window(LOG_PATH, start, now)
    report = build_report(start, now, ban_ips, unban_ips, found_ips, fails)
    subject = f"{SUBJECT_PREFIX} Fail2Ban 报告 {now.strftime('%Y-%m-%d %H:%M:%S')}"

    print("\n=== Report Begin ===\n" + report + "\n=== Report End ===\n")

    if MAIL_PROVIDER == "smtp":
        send_mail_smtp(subject, report)
    elif MAIL_PROVIDER == "resend":
        send_mail_resend(subject, report)
    else:
        raise ValueError(f"Unknown MAIL_PROVIDER: {MAIL_PROVIDER}")


def main():
    interval = parse_interval(INTERVAL_STR)
    print(f"[INFO] LOG_PATH={LOG_PATH}")
    print(f"[INFO] INTERVAL={interval}")
    print(f"[INFO] MAIL_PROVIDER={MAIL_PROVIDER}")

    while True:
        now = datetime.now()
        try:
            run_once(now, interval)
        except Exception as e:
            print(f"[ERROR] run_once failed: {e}")
        time.sleep(interval.total_seconds())


if __name__ == "__main__":
    main()
