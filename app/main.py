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
COLLECT_INTERVAL = int(os.getenv("COLLECT_INTERVAL", "300"))  # 数据收集周期(秒)，对应5分钟
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
INTERVAL_RE = re.compile(r"^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$")

class DataCollector:
    """数据收集类和缓存"""
    
    def __init__(self, cache_path: str):
        self.cache_path = cache_path
        self.data = self._load_cache()
    
    def _load_cache(self) -> Dict:
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
            'last_position': 0,    # 上次读取的文件位置
            'last_inode': None,    # 上次读取的文件inode
        }
    
    def _save_cache(self):
        """保存数据到缓存文件"""
        try:
            with open(self.cache_path, 'wb') as f:
                pickle.dump(self.data, f)
        except Exception as e:
            print(f"[WARN] 保存缓存失败: {e}")
    
    def _parse_timestamp(self, ts_str: str) -> datetime:
        """解析时间戳"""
        return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    
    def _get_file_inode(self, filepath: str) -> int:
        """获取文件inode"""
        try:
            return os.stat(filepath).st_ino
        except:
            return None
    
    def collect_data(self, log_path: str):
        """收集日志数据"""
        if not os.path.exists(log_path):
            print(f"[ERROR] 日志文件不存在: {log_path}")
            return
        
        current_inode = self._get_file_inode(log_path)
        
        # 检查文件是否被轮转
        if self.data['last_inode'] and current_inode != self.data['last_inode']:
            print("[INFO] 检测到日志文件轮转，重置读取位置")
            self.data['last_position'] = 0
        
        self.data['last_inode'] = current_inode
        
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                # 跳转到上次读取的位置
                f.seek(self.data['last_position'])
                
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    # 解析时间戳
                    ts_match = TS_RE.match(line)
                    if not ts_match:
                        continue
                    
                    try:
                        timestamp = self._parse_timestamp(ts_match.group(1))
                    except:
                        continue
                    
                    # 检查Ban事件
                    if ban_match := BAN_RE.search(line):
                        ip = ban_match.group(1)
                        self.data['ban_events'].append((timestamp, ip))
                    
                    # 检查Unban事件
                    elif unban_match := UNBAN_RE.search(line):
                        ip = unban_match.group(1)
                        self.data['unban_events'].append((timestamp, ip))
                    
                    # 检查Found事件
                    elif FOUND_RE.search(line):
                        # 尝试从行中提取IP地址
                        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                        ip = ip_match.group(0) if ip_match else "unknown"
                        self.data['found_events'].append((timestamp, ip))
                
                # 更新文件读取位置
                self.data['last_position'] = f.tell()
        
        except Exception as e:
            print(f"[ERROR] 读取日志文件失败: {e}")
        
        # 保存缓存
        self._save_cache()
    
    def get_events_in_window(self, start_time: datetime, end_time: datetime) -> Dict:
        """获取指定时间窗口内的事件"""
        ban_events = [(ts, ip) for ts, ip in self.data['ban_events'] 
                      if start_time <= ts <= end_time]
        unban_events = [(ts, ip) for ts, ip in self.data['unban_events'] 
                        if start_time <= ts <= end_time]
        found_events = [(ts, ip) for ts, ip in self.data['found_events'] 
                        if start_time <= ts <= end_time]
        
        return {
            'ban_events': ban_events,
            'unban_events': unban_events,
            'found_events': found_events
        }
    
    def check_log_file_status(self, log_path: str, start_time: datetime, end_time: datetime) -> Dict:
        """
        检查日志文件在指定时间窗口内的状态
        返回：
        {
            'has_new_entries': bool,  # 是否有新条目
            'total_lines': int,       # 新条目总数
            'last_entry_time': datetime  # 最后一条条目时间
        }
        """
        result = {
            'has_new_entries': False,
            'total_lines': 0,
            'last_entry_time': None
        }
        
        if not os.path.exists(log_path):
            print(f"[ERROR] 日志文件不存在: {log_path}")
            return result
        
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines_in_window = []
                last_valid_time = None
                
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    # 解析时间戳
                    ts_match = TS_RE.match(line)
                    if not ts_match:
                        continue
                    
                    try:
                        timestamp = self._parse_timestamp(ts_match.group(1))
                        last_valid_time = timestamp
                        
                        # 检查是否在时间窗口内
                        if start_time <= timestamp <= end_time:
                            lines_in_window.append((timestamp, line))
                    except:
                        continue
                
                result['has_new_entries'] = len(lines_in_window) > 0
                result['total_lines'] = len(lines_in_window)
                result['last_entry_time'] = last_valid_time
                
                if lines_in_window:
                    # 获取时间窗口内最后一条记录的时间
                    result['last_entry_time'] = max(ts for ts, _ in lines_in_window)
        
        except Exception as e:
            print(f"[ERROR] 检查日志文件状态失败: {e}")
        
        return result
    
    def cleanup_old_events(self, cutoff_time: datetime):
        """清理过期事件"""
        self.data['ban_events'] = [(ts, ip) for ts, ip in self.data['ban_events'] 
                                   if ts >= cutoff_time]
        self.data['unban_events'] = [(ts, ip) for ts, ip in self.data['unban_events'] 
                                     if ts >= cutoff_time]
        self.data['found_events'] = [(ts, ip) for ts, ip in self.data['found_events'] 
                                     if ts >= cutoff_time]
        self._save_cache()

def parse_interval(interval_str: str) -> int:
    """解析时间间隔字符串，返回秒数"""
    match = INTERVAL_RE.match(interval_str)
    if not match:
        raise ValueError(f"Invalid interval format: {interval_str}")
    
    hours = int(match.group(1) or 0)
    minutes = int(match.group(2) or 0)
    seconds = int(match.group(3) or 0)
    
    return hours * 3600 + minutes * 60 + seconds

def determine_status_type(ban_count: int, unban_count: int, found_count: int, 
                         log_status: Dict) -> Dict:
    """
    根据事件数量和日志状态确定报告类型
    返回：
    {
        'report_type': 'normal' | 'status_normal' | 'status_error',
        'status_message': str,
        'log_file_status': str,
        'status_detail': str
    }
    """
    # 如果有任何事件，使用正常报告
    if ban_count > 0 or unban_count > 0 or found_count > 0:
        return {
            'report_type': 'normal',
            'status_message': '',
            'log_file_status': '',
            'status_detail': ''
        }
    
    # 无事件时，检查日志文件状态
    if log_status['has_new_entries']:
        # 有新日志条目但无匹配事件
        return {
            'report_type': 'status_normal',
            'status_message': '服务状态正常',
            'log_file_status': '日志文件正常',
            'status_detail': f'没有发现新的拦截内容（检查了 {log_status["total_lines"]} 条日志记录）'
        }
    else:
        # 无新日志条目
        return {
            'report_type': 'status_error',
            'status_message': '服务状态异常',
            'log_file_status': '日志文件没有新内容',
            'status_detail': '请检查容器访问日志文件fail2ban.log的相关配置'
        }

def generate_report_html(ban_ips: List[str], unban_ips: List[str], 
                        found_counter: Counter, start_time: datetime, 
                        end_time: datetime) -> str:
    """生成HTML报告"""
    try:
        with open('/app/report-template.html', 'r', encoding='utf-8') as f:
            template = f.read()
    except:
        # 如果模板文件不存在，使用简单的HTML
        template = """
        <html>
        <body>
        <h2>Fail2Ban 报告</h2>
        <p>时间范围: {{start_time}} - {{end_time}}</p>
        <h3>Ban IP ({{ban_count}})</h3>
        <ul>{{ban_list}}</ul>
        <h3>Unban IP ({{unban_count}})</h3>
        <ul>{{unban_list}}</ul>
        <h3>失败尝试 Top {{top_n}}</h3>
        <ul>{{found_list}}</ul>
        </body>
        </html>
        """
    
    # 生成Ban IP列表
    ban_list = "".join([f"<li>{ip}</li>" for ip in ban_ips]) if ban_ips else "<li>无</li>"
    
    # 生成Unban IP列表
    unban_list = "".join([f"<li>{ip}</li>" for ip in unban_ips]) if unban_ips else "<li>无</li>"
    
    # 生成失败尝试Top N列表
    top_found = found_counter.most_common(TOP_N)
    found_list = "".join([f"<li>{ip}: {count} 次</li>" for ip, count in top_found]) if top_found else "<li>无</li>"
    
    # 替换模板变量
    html = template.replace("{{start_time}}", start_time.strftime("%Y-%m-%d %H:%M:%S"))
    html = html.replace("{{end_time}}", end_time.strftime("%Y-%m-%d %H:%M:%S"))
    html = html.replace("{{ban_count}}", str(len(ban_ips)))
    html = html.replace("{{unban_count}}", str(len(unban_ips)))
    html = html.replace("{{ban_list}}", ban_list)
    html = html.replace("{{unban_list}}", unban_list)
    html = html.replace("{{found_list}}", found_list)
    html = html.replace("{{top_n}}", str(TOP_N))
    
    return html

def generate_status_html(status_info: Dict, start_time: datetime, end_time: datetime) -> str:
    """生成状态报告HTML"""
    try:
        # 尝试读取项目中的status-template.html
        template_paths = ['/app/status-template.html', '/home/ubuntu/status-template.html']
        template = None
        
        for path in template_paths:
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    template = f.read()
                    break
            except:
                continue
        
        if not template:
            raise FileNotFoundError("No template found")
            
    except:
        # 如果模板文件不存在，使用简单的HTML
        template = """
        <html>
        <body>
        <h2>{{SUBJECT_PREFIX}} 服务状态报告</h2>
        <p>时间范围: {{start}} - {{end}}</p>
        <h3>{{status_type}}</h3>
        <p>{{log_file_status}}</p>
        <p>{{status_detail}}</p>
        </body>
        </html>
        """
    
    # 替换模板变量
    html = template.replace("{{SUBJECT_PREFIX}}", SUBJECT_PREFIX)
    html = html.replace("{{start}}", start_time.strftime("%Y-%m-%d %H:%M:%S"))
    html = html.replace("{{end}}", end_time.strftime("%Y-%m-%d %H:%M:%S"))
    html = html.replace("{{status_type}}", status_info['status_message'])
    html = html.replace("{{log_file_status}}", status_info['log_file_status'])
    html = html.replace("{{status_detail}}", status_info['status_detail'])
    
    return html

def send_email_smtp(subject: str, html_body: str):
    """通过SMTP发送邮件"""
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = SMTP_FROM
    msg['To'] = ', '.join(MAIL_TO)
    
    html_part = MIMEText(html_body, 'html', 'utf-8')
    msg.attach(html_part)
    
    context = ssl.create_default_context()
    
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        if SMTP_TLS:
            server.starttls(context=context)
        server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)

def send_email_resend(subject: str, html_body: str):
    """通过Resend API发送邮件"""
    if not requests:
        raise Exception("requests library not available")
    
    url = "https://api.resend.com/emails"
    headers = {
        "Authorization": f"Bearer {RESEND_API_KEY}",
        "Content-Type": "application/json"
    }
    
    data = {
        "from": RESEND_FROM,
        "to": MAIL_TO,
        "subject": subject,
        "html": html_body
    }
    
    response = requests.post(url, headers=headers, json=data)
    response.raise_for_status()

def send_email(subject: str, html_body: str):
    """发送邮件"""
    try:
        if MAIL_PROVIDER == "resend":
            send_email_resend(subject, html_body)
        else:
            send_email_smtp(subject, html_body)
        print(f"[INFO] 邮件发送成功: {subject}")
    except Exception as e:
        print(f"[ERROR] 邮件发送失败: {e}")

def main():
    """主函数"""
    print(f"[INFO] Fail2Ban Reporter 启动")
    print(f"[INFO] 日志路径: {LOG_PATH}")
    print(f"[INFO] 报告间隔: {INTERVAL_STR}")
    print(f"[INFO] 收集间隔: {COLLECT_INTERVAL}秒")
    print(f"[INFO] 邮件提供商: {MAIL_PROVIDER}")
    print(f"[INFO] 收件人: {', '.join(MAIL_TO)}")
    
    # 解析间隔
    try:
        interval_seconds = parse_interval(INTERVAL_STR)
        collect_interval_seconds = COLLECT_INTERVAL
    except ValueError as e:
        print(f"[ERROR] {e}")
        return
    
    # 初始化数据收集器
    collector = DataCollector(DATA_CACHE_PATH)
    
    # 主循环
    while True:
        try:
            # 收集数据
            collector.collect_data(LOG_PATH)
            
            # 计算时间窗口
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(seconds=interval_seconds)
            
            # 获取时间窗口内的事件
            events = collector.get_events_in_window(start_time, end_time)
            
            # 提取IP列表
            ban_ips = [ip for _, ip in events['ban_events']]
            unban_ips = [ip for _, ip in events['unban_events']]
            found_ips = [ip for _, ip in events['found_events']]
            found_counter = Counter(found_ips)
            
            # 检查日志文件状态（用于无内容状态汇报）
            log_status = collector.check_log_file_status(LOG_PATH, start_time, end_time)
            
            # 确定报告类型
            status_info = determine_status_type(len(ban_ips), len(unban_ips), 
                                              len(found_ips), log_status)
            
            # 生成报告和发送邮件
            if status_info['report_type'] == 'normal':
                # 正常报告（有事件）
                html_body = generate_report_html(ban_ips, unban_ips, found_counter, 
                                               start_time, end_time)
                subject = f"{SUBJECT_PREFIX} 报告 - {end_time.strftime('%Y-%m-%d %H:%M:%S')}"
                print(f"[INFO] 生成正常报告: Ban={len(ban_ips)}, Unban={len(unban_ips)}, Found={len(found_ips)}")
            else:
                # 状态报告（无事件）
                html_body = generate_status_html(status_info, start_time, end_time)
                if status_info['report_type'] == 'status_normal':
                    subject = f"{SUBJECT_PREFIX} 状态正常 - {end_time.strftime('%Y-%m-%d %H:%M:%S')}"
                    print(f"[INFO] 生成状态正常报告: 日志条目={log_status['total_lines']}")
                else:
                    subject = f"{SUBJECT_PREFIX} 状态异常 - {end_time.strftime('%Y-%m-%d %H:%M:%S')}"
                    print(f"[INFO] 生成状态异常报告: 无新日志条目")
            
            send_email(subject, html_body)
            
            # 清理过期事件（保留最近7天的数据）
            cutoff_time = end_time - timedelta(days=7)
            collector.cleanup_old_events(cutoff_time)
            
            print(f"[INFO] 报告完成，等待 {interval_seconds} 秒...")
            time.sleep(interval_seconds)
            
        except KeyboardInterrupt:
            print("[INFO] 程序被用户中断")
            break
        except Exception as e:
            print(f"[ERROR] 运行时错误: {e}")
            time.sleep(60)  # 出错时等待1分钟再重试

if __name__ == "__main__":
    main()
