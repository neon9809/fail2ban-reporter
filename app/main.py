import os
import re
import time
import smtplib
import ssl
import json
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Tuple, Dict, Counter
from collections import Counter
import pickle
try:
    import requests
except Exception:
    requests = None

LOG_PATH = os.getenv("LOG_PATH", "/var/log/fail2ban.log")
INTERVAL_STR = os.getenv("INTERVAL", "1h")
COLLECT_INTERVAL = int(os.getenv("COLLECT_INTERVAL", "300"))  # 数据收集间隔(秒)，默认5分钟
DATA_CACHE_PATH = os.getenv("DATA_CACHE_PATH", "/tmp/fail2ban_cache.pkl")  # 缓存文件路径
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

# Timezone handling
if tz := os.getenv("TZ"):
    os.environ["TZ"] = tz
    try:
        time.tzset()
    except Exception:
        pass

# Regexes
TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")
BAN_RE = re.compile(r"Ban\s+([^\s]+)")
UNBAN_RE = re.compile(r"Unban\s+([^\s]+)")
FOUND_RE = re.compile(r"Found\b")
INTERVAL_RE = re.compile(r"^(?:(?P<h>\d+)h)?(?:(?P<m>\d+)m)?(?:(?P<s>\d+)s)?$")

class DataCollector:
    """数据收集和缓存类"""
    
    def __init__(self, cache_path: str):
        self.cache_path = cache_path
        self.data = self.load_cache()
        
    def load_cache(self) -> Dict:
        """从缓存文件加载数据"""
        try:
            if os.path.exists(self.cache_path):
                with open(self.cache_path, 'rb') as f:
                    return pickle.load(f)
        except Exception as e:
            print(f"[WARN] 加载缓存失败: {e}")
        
        return {
            'ban_events': [],      # [(timestamp, ip), ...]
            'unban_events': [],    # [(timestamp, ip), ...]
            'found_events': [],    # [(timestamp, ip), ...]
            'last_processed': datetime.now() - timedelta(minutes=10)  # 修复：设置默认值
        }
    
    def save_cache(self):
        """保存数据到缓存文件"""
        try:
            # 确保目录存在
            cache_dir = os.path.dirname(self.cache_path)
            if cache_dir:  # 防止空路径
                os.makedirs(cache_dir, exist_ok=True)
            with open(self.cache_path, 'wb') as f:
                pickle.dump(self.data, f)
        except Exception as e:
            print(f"[ERROR] 保存缓存失败: {e}")
    
    def collect_new_data(self, log_path: str, since: datetime = None):
        """收集新的日志数据"""
        # 修复：确保 since 始终有有效值
        if since is None:
            since = self.data.get('last_processed')
            if since is None:
                since = datetime.now() - timedelta(minutes=10)
        
        now = datetime.now()
        
        # 确保 since 不会比 now 更新
        if since > now:
            since = now - timedelta(minutes=5)
            
        try:
            ban_ips, unban_ips, found_ips, _ = parse_log_window(log_path, since, now)
        except Exception as e:
            print(f"[ERROR] 解析日志文件失败: {e}")
            return
        
        # 添加到缓存数据中（记录实际的事件时间，而不是处理时间）
        for ip in ban_ips:
            self.data['ban_events'].append((now, ip))
        
        for ip in unban_ips:
            self.data['unban_events'].append((now, ip))
            
        for ip in found_ips:
            self.data['found_events'].append((now, ip))
        
        # 更新最后处理时间
        self.data['last_processed'] = now
        
        # 清理过期数据（保留比报告间隔长一些的数据）
        self.cleanup_old_data(timedelta(days=1))  # 保留1天的数据
        
        # 保存缓存
        self.save_cache()
        
        if ban_ips or unban_ips or found_ips:
            print(f"[INFO] 收集数据完成: Ban={len(ban_ips)}, Unban={len(unban_ips)}, Found={len(found_ips)}")
        else:
            print(f"[DEBUG] 本次收集无新数据 (检查时间: {since} - {now})")
    
    def cleanup_old_data(self, keep_duration: timedelta):
        """清理过期数据"""
        cutoff = datetime.now() - keep_duration
        
        original_ban_count = len(self.data['ban_events'])
        original_unban_count = len(self.data['unban_events'])
        original_found_count = len(self.data['found_events'])
        
        self.data['ban_events'] = [(ts, ip) for ts, ip in self.data['ban_events'] if ts > cutoff]
        self.data['unban_events'] = [(ts, ip) for ts, ip in self.data['unban_events'] if ts > cutoff]
        self.data['found_events'] = [(ts, ip) for ts, ip in self.data['found_events'] if ts > cutoff]
        
        cleaned_ban = original_ban_count - len(self.data['ban_events'])
        cleaned_unban = original_unban_count - len(self.data['unban_events'])
        cleaned_found = original_found_count - len(self.data['found_events'])
        
        if cleaned_ban > 0 or cleaned_unban > 0 or cleaned_found > 0:
            print(f"[DEBUG] 清理过期数据: Ban={cleaned_ban}, Unban={cleaned_unban}, Found={cleaned_found}")
    
    def get_report_data(self, start: datetime, end: datetime) -> Tuple[List[str], List[str], List[str], int]:
        """获取指定时间范围内的报告数据"""
        ban_ips = [ip for ts, ip in self.data['ban_events'] if start <= ts <= end]
        unban_ips = [ip for ts, ip in self.data['unban_events'] if start <= ts <= end]
        found_ips = [ip for ts, ip in self.data['found_events'] if start <= ts <= end]
        fails_count = len(found_ips)
        
        return ban_ips, unban_ips, found_ips, fails_count

def parse_interval(s: str) -> timedelta:
    interval_match = INTERVAL_RE.match(s.strip())
    if not interval_match:
        raise ValueError(f"Invalid INTERVAL: '{s}'. Use forms like '30m', '15m', '45s'.")
    h = int(interval_match.groupdict().get("h") or 0)
    m_ = int(interval_match.groupdict().get("m") or 0)
    s_ = int(interval_match.groupdict().get("s") or 0)
    if h == 0 and m_ == 0 and s_ == 0:
        raise ValueError(f"Invalid INTERVAL: '{s}'. Must include h/m/s.")
    return timedelta(hours=h, minutes=m_, seconds=s_)

def parse_log_window(path: str, start: datetime, end: datetime) -> Tuple[List[str], List[str], List[str], int]:
    """
    解析指定时间窗口内的日志
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

            if match_ban := BAN_RE.search(line):
                ip = match_ban.group(1)
                ban_ips.append(ip)
            elif match_unban := UNBAN_RE.search(line):
                ip = match_unban.group(1)
                unban_ips.append(ip)
            elif FOUND_RE.search(line):
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
    uniq_fails = sorted(set(found_ips))

    # Top N IPs by Found occurrences
    top_fails = Counter(found_ips).most_common(top_n)

    lines = []
    lines.append(f"时间范围: {start} - {end}")
    lines.append("")
    lines.append(f"Ban IP 数量: {len(uniq_ban)}")
    lines.append(f"Unban IP 数量: {len(uniq_unban)}")
    lines.append(f"失败尝试次数(Found): {fails}")
    lines.append("")
    lines.append("Ban IP List:")
    if uniq_ban:
        for ip in uniq_ban:
            lines.append(f"  - {ip}")
    else:
        lines.append("  - (无)")
    lines.append("")
    lines.append("Unban IP List:")
    if uniq_unban:
        for ip in uniq_unban:
            lines.append(f"  - {ip}")
    else:
        lines.append("  - (无)")
    lines.append("")
    if top_fails:
        lines.append(f"失败尝试次数最多的{top_n}个IP:")
        for ip, cnt in top_fails:
            lines.append(f"  - {ip} ({cnt})")
    lines.append("")
    return "\n".join(lines)

def build_html_report(start: datetime, end: datetime,
                     ban_ips: List[str],
                     unban_ips: List[str],
                     found_ips: List[str],
                     fails: int,
                     top_n: int) -> str:
    """
    Build HTML report using Template class
    """
    from string import Template
    uniq_ban = sorted(set(ban_ips))
    uniq_unban = sorted(set(unban_ips))
    uniq_fails = sorted(set(found_ips))
    top_fails = Counter(found_ips).most_common(top_n)

    # Read HTML template
    template_path = os.path.join(os.path.dirname(__file__), "report-template.html")
    try:
        with open(template_path, "r", encoding="utf-8") as f:
            template_content = f.read()
    except FileNotFoundError:
        # Fallback template if file not found
        template_content = """
        <html>
        <body>
        <h1>$SUBJECT_PREFIX IP拦截报告</h1>
        <p>时间范围: $start - $end</p>
        <p>Ban IP 数量: $ban_count</p>
        <p>Unban IP 数量: $unban_count</p>
        <p>失败尝试计数: $fail_count</p>
        </body>
        </html>
        """

    # Format IP lists for display
    ban_ips_str = "  ".join(uniq_ban) if uniq_ban else " - "
    unban_ips_str = "  ".join(uniq_unban) if uniq_unban else " - "
    
    # Format top fail IPs and counts with line breaks
    if top_fails:
        counts_html = "<br/>".join(str(cnt) for _, cnt in top_fails)
        ips_html = "<br/>".join(ip for ip, _ in top_fails)
    else:
        counts_html = "无"
        ips_html = "无"

    # Use Template class for safe substitution
    template_obj = Template(template_content)
    html_content = template_obj.safe_substitute(
        SUBJECT_PREFIX=SUBJECT_PREFIX,
        start=start.strftime('%Y-%m-%d %H:%M:%S'),
        end=end.strftime('%Y-%m-%d %H:%M:%S'),
        TOP_N=top_n,
        ban_count=len(uniq_ban),
        unban_count=len(uniq_unban),
        fail_count=len(uniq_fails),
        ban_ips=ban_ips_str if ban_ips_str else " - ",
        unban_ips=unban_ips_str if unban_ips_str else " - ",
        top_fail_count=counts_html,
        top_fail_ips=ips_html
    )
    return html_content

def send_mail_smtp(subject: str, body: str, html_body: str = None):
    if not MAIL_TO:
        print("[WARN] MAIL_TO not set; skip sending.")
        return

    # Create multipart message
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = ", ".join(MAIL_TO)

    # Add text part
    text_part = MIMEText(body, "plain", "utf-8")
    msg.attach(text_part)

    # Add HTML part if provided
    if html_body:
        html_part = MIMEText(html_body, "html", "utf-8")
        msg.attach(html_part)

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

def send_mail_resend(subject: str, body: str, html_body: str = None):
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
    # Add HTML content if provided
    if html_body:
        payload["html"] = html_body

    headers = {
        "Authorization": f"Bearer {RESEND_API_KEY}",
        "Content-Type": "application/json",
    }
    resp = requests.post(url, headers=headers, data=json.dumps(payload), timeout=20)
    if resp.status_code >= 300:
        raise RuntimeError(f"Resend API error: {resp.status_code} {resp.text}")

def send_report(collector: DataCollector, now: datetime, interval: timedelta):
    """发送报告邮件"""
    start = now - interval
    ban_ips, unban_ips, found_ips, fails = collector.get_report_data(start, now)

    # Build both text and HTML reports
    text_report = build_report(start, now, ban_ips, unban_ips, found_ips, fails, TOP_N)
    html_report = build_html_report(start, now, ban_ips, unban_ips, found_ips, fails, TOP_N)

    subject = f"{SUBJECT_PREFIX} Fail2Ban 报告 {now.strftime('%Y-%m-%d %H:%M:%S')}"

    print(f"\n=== Report Begin ===\n" + text_report + "\n=== Report End ===\n")

    if MAIL_PROVIDER == "smtp":
        send_mail_smtp(subject, text_report, html_report)
    elif MAIL_PROVIDER == "resend":
        send_mail_resend(subject, text_report, html_report)
    else:
        raise ValueError(f"Unknown MAIL_PROVIDER: {MAIL_PROVIDER}")

def main():
    interval = parse_interval(INTERVAL_STR)
    collector = DataCollector(DATA_CACHE_PATH)
    
    print(f"[INFO] LOG_PATH={LOG_PATH}")
    print(f"[INFO] INTERVAL={interval}")
    print(f"[INFO] COLLECT_INTERVAL={COLLECT_INTERVAL}s")
    print(f"[INFO] DATA_CACHE_PATH={DATA_CACHE_PATH}")
    print(f"[INFO] MAIL_PROVIDER={MAIL_PROVIDER}")

    now = datetime.now()
    
    # 检查是否是首次运行（缓存文件不存在或为空）
    is_first_run = not os.path.exists(DATA_CACHE_PATH) or len(collector.data.get('ban_events', [])) == 0
    
    if is_first_run:
        # 首次运行只报告最近1小时
        first_interval = timedelta(hours=1)
        last_report_time = now - first_interval
        print(f"[INFO] 首次运行，将报告最近 {first_interval} 的数据")
    else:
        # 正常运行报告完整间隔
        last_report_time = now - interval
    
    print(f"[INFO] 服务启动，下次报告时间: {last_report_time + interval}")
    
    while True:
        current_time = datetime.now()
        
        try:
            # 每次循环都收集数据
            collector.collect_new_data(LOG_PATH)
            
            # 检查是否到了发送报告的时间
            if current_time - last_report_time >= interval:
                print(f"[INFO] 准备发送报告 (上次报告: {last_report_time})")
                send_report(collector, current_time, interval)
                last_report_time = current_time
                print(f"[INFO] 报告发送完成，下次报告时间: {last_report_time + interval}")
            else:
                next_report_in = interval - (current_time - last_report_time)
                print(f"[DEBUG] 距离下次报告还有: {next_report_in}")
                
        except Exception as e:
            print(f"[ERROR] 处理失败: {e}")
            import traceback
            traceback.print_exc()  # 打印详细错误信息
        
        # 等待收集间隔
        time.sleep(COLLECT_INTERVAL)

if __name__ == "__main__":
    main()