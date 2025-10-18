import os
import re
import time
import smtplib
import ssl
import json
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
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

# Email retry configuration
EMAIL_RETRY_ENABLED = os.getenv("EMAIL_RETRY", "false").lower() == "true"
EMAIL_RETRY_INTERVALS = [300, 600, 3600, 10800]  # 5分钟、10分钟、1小时、3小时（秒）
EMAIL_RETRY_CACHE_PATH = os.getenv("EMAIL_RETRY_CACHE_PATH", "/tmp/email_retry_queue.pkl")

# AbuseIPDB config
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

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

class EmailRetryQueue:
    """邮件重试队列管理类"""
    
    def __init__(self, cache_path: str):
        self.cache_path = cache_path
        self.queue = self._load_queue()
    
    def _load_queue(self) -> List[Dict]:
        """从缓存文件加载重试队列"""
        try:
            if os.path.exists(self.cache_path):
                with open(self.cache_path, 'rb') as f:
                    return pickle.load(f)
        except Exception as e:
            print(f"[WARN] 加载邮件重试队列失败: {e}")
        return []
    
    def _save_queue(self):
        """保存重试队列到缓存文件"""
        try:
            with open(self.cache_path, 'wb') as f:
                pickle.dump(self.queue, f)
        except Exception as e:
            print(f"[WARN] 保存邮件重试队列失败: {e}")
    
    def add_email(self, subject: str, html_body: str):
        """添加邮件到重试队列"""
        email_task = {
            'subject': subject,
            'html_body': html_body,
            'retry_count': 0,
            'next_retry_time': datetime.now(timezone.utc) + timedelta(seconds=EMAIL_RETRY_INTERVALS[0]),
            'created_at': datetime.now(timezone.utc)
        }
        self.queue.append(email_task)
        self._save_queue()
        print(f"[INFO] 邮件已加入重试队列: {subject}")
    
    def process_retry_queue(self):
        """处理重试队列中的邮件"""
        if not self.queue:
            return
        
        current_time = datetime.now(timezone.utc)
        remaining_queue = []
        
        for email_task in self.queue:
            # 检查是否到达重试时间
            if current_time >= email_task['next_retry_time']:
                print(f"[INFO] 重试发送邮件 (第{email_task['retry_count'] + 1}次): {email_task['subject']}")
                
                try:
                    # 尝试发送邮件
                    if MAIL_PROVIDER == "resend":
                        send_email_resend(email_task['subject'], email_task['html_body'])
                    else:
                        send_email_smtp(email_task['subject'], email_task['html_body'])
                    
                    print(f"[INFO] 邮件重试发送成功: {email_task['subject']}")
                    # 发送成功，不再加入队列
                    
                except Exception as e:
                    print(f"[ERROR] 邮件重试发送失败 (第{email_task['retry_count'] + 1}次): {e}")
                    
                    # 增加重试计数
                    email_task['retry_count'] += 1
                    
                    # 检查是否还有重试机会
                    if email_task['retry_count'] < len(EMAIL_RETRY_INTERVALS):
                        # 计算下次重试时间
                        email_task['next_retry_time'] = current_time + timedelta(
                            seconds=EMAIL_RETRY_INTERVALS[email_task['retry_count']]
                        )
                        remaining_queue.append(email_task)
                        print(f"[INFO] 将在 {EMAIL_RETRY_INTERVALS[email_task['retry_count']]} 秒后重试")
                    else:
                        print(f"[ERROR] 邮件发送失败，已达到最大重试次数: {email_task['subject']}")
            else:
                # 未到重试时间，保留在队列中
                remaining_queue.append(email_task)
        
        self.queue = remaining_queue
        self._save_queue()

def check_abuseipdb_quota(api_key: str) -> int:
    """检查 AbuseIPDB API 的剩余查询额度"""
    if not requests:
        print("[ERROR] requests 库未安装，无法使用 AbuseIPDB 功能")
        return 0
    
    try:
        headers = {
            'Key': api_key,
            'Accept': 'application/json',
        }
        # 使用一个保留地址进行虚拟查询，以获取响应头
        response = requests.get('https://api.abuseipdb.com/api/v2/check', 
                              headers=headers, 
                              params={'ipAddress': '127.0.0.1'}, 
                              timeout=10)
        remaining = int(response.headers.get('X-RateLimit-Remaining', 0))
        daily_limit = int(response.headers.get('X-RateLimit-Limit', 0))
        print(f"[INFO] AbuseIPDB 剩余查询额度: {remaining}/{daily_limit}")
        return remaining
    except Exception as e:
        print(f"[ERROR] 检查 AbuseIPDB 配额失败: {e}")
        return 0

def get_abuseipdb_report(ip_address: str, api_key: str) -> dict | None:
    """获取单个 IP 地址的 AbuseIPDB 报告"""
    if not requests:
        print("[ERROR] requests 库未安装，无法使用 AbuseIPDB 功能")
        return None
    
    try:
        headers = {
            'Key': api_key,
            'Accept': 'application/json',
        }
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': '90',
            'verbose': '' # 获取详细报告
        }
        response = requests.get('https://api.abuseipdb.com/api/v2/check', 
                              headers=headers, 
                              params=params, 
                              timeout=10)
        if response.status_code == 200:
            return response.json().get('data', {})
        else:
            print(f"[ERROR] AbuseIPDB API 请求失败 ({ip_address}): {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print(f"[ERROR] 获取 AbuseIPDB 报告失败 ({ip_address}): {e}")
        return None

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
        '''解析时间戳，使用环境变量指定的时区'''
        # 解析时间字符串（不带时区信息）
        naive_dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
    
    # 获取环境变量中的时区设置
        tz_str = os.getenv('TZ', 'UTC')
    
        try:
        # 创建时区对象
            local_tz = ZoneInfo(tz_str)
        except Exception as e:
        # 如果时区无效，回退到 UTC
            print(f"[WARN] 无法解析时区 '{tz_str}': {e}，使用 UTC")
            local_tz = timezone.utc
    
    # 将日志时间戳解释为本地时区的时间
        local_dt = naive_dt.replace(tzinfo=local_tz)
    
    # 转换为 UTC 时间用于统一比较
        utc_dt = local_dt.astimezone(timezone.utc)
    
        return utc_dt
    
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
        raise ValueError(f"无效的时间间隔格式: {interval_str}")
    
    hours = int(match.group(1) or 0)
    minutes = int(match.group(2) or 0)
    seconds = int(match.group(3) or 0)
    
    total_seconds = hours * 3600 + minutes * 60 + seconds
    
    if total_seconds == 0:
        raise ValueError("时间间隔不能为0")
    
    return total_seconds

def load_template(template_name: str) -> str | None:
    """加载HTML模板文件"""
    try:
        # 尝试从多个可能的路径加载
        possible_paths = [
            os.path.join(os.path.dirname(__file__), template_name),
            os.path.join("/app", template_name),
            template_name
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                with open(path, 'r', encoding='utf-8') as f:
                    return f.read()
        
        print(f"[WARN] 模板文件未找到: {template_name}")
        return None
    except Exception as e:
        print(f"[ERROR] 加载模板文件失败: {e}")
        return None

def replace_template_variables(template: str, variables: Dict[str, str]) -> str:
    """替换模板中的变量"""
    result = template
    for key, value in variables.items():
        placeholder = f"${key}"
        result = result.replace(placeholder, str(value))
    return result

def determine_status_type(ban_count: int, unban_count: int, found_count: int, 
                         log_status: Dict) -> Dict:
    """
    确定报告类型
    返回：
    {
        'report_type': str,  # 'normal', 'status_normal', 'status_error'
        'status_message': str,
        'log_file_status': str,
        'status_detail': str
    }
    """
    # 如果有任何事件，返回正常报告
    if ban_count > 0 or unban_count > 0 or found_count > 0:
        return {
            'report_type': 'normal',
            'status_message': '',
            'log_file_status': '',
            'status_detail': ''
        }
    
    # 没有事件，检查日志文件状态
    if log_status['has_new_entries']:
        # 日志文件有新条目，但没有Ban/Unban/Found事件
        return {
            'report_type': 'status_normal',
            'status_message': '服务运行正常，无新的安全事件',
            'log_file_status': '日志文件状态: 正常更新',
            'status_detail': f'在此周期内，日志文件共有 {log_status["total_lines"]} 条新记录，但未检测到任何 Ban、Unban 或失败尝试事件。这表明 Fail2ban 服务正在正常运行，只是没有触发任何封禁操作。'
        }
    else:
        # 日志文件没有新条目
        last_time_str = "未知"
        if log_status['last_entry_time']:
            last_time_str = log_status['last_entry_time'].strftime("%Y-%m-%d %H:%M:%S")
        
        return {
            'report_type': 'status_error',
            'status_message': '警告: 日志文件无新内容',
            'log_file_status': '日志文件状态: 无新记录',
            'status_detail': f'在此周期内，日志文件没有任何新记录。最后一条日志的时间为: {last_time_str}。这可能表明 Fail2ban 服务未在运行，或者日志文件挂载存在问题。请检查 Fail2ban 服务状态和日志文件路径配置。'
        }

def format_abuseipdb_reports_html(abuseipdb_reports: Dict) -> str:
    """格式化 AbuseIPDB 报告为 HTML"""
    if not abuseipdb_reports:
        return ""
    
    # 使用与原模板一致的结构
    html = '''
                <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%">
                  <tr>
                    <td style="padding: 20px 0 0 0;">
                      <span style="color:#000000; font-size:1.2rem; font-weight:bold;">AbuseIPDB 查询结果</span><br><br><span style="color:#565656;">'''
    
    for ip, report in abuseipdb_reports.items():
        # 提取所有字段信息
        confidence_score = report.get('abuseConfidenceScore', 0)
        is_whitelisted = "是" if report.get('isWhitelisted', False) else "否"
        country_code = report.get('countryCode', '未知')
        country_name = report.get('countryName', '未知')
        usage_type = report.get('usageType', '未知')  # 用户要求不能省略
        isp = report.get('isp', '未知')
        domain = report.get('domain', '未知')
        total_reports = report.get('totalReports', 0)
        num_distinct_users = report.get('numDistinctUsers', 0)
        last_reported_at = report.get('lastReportedAt', '未知')
        is_public = "是" if report.get('isPublic', False) else "否"
        ip_version = report.get('ipVersion', '未知')
        is_tor = "是" if report.get('isTor', False) else "否"
        hostnames = report.get('hostnames', [])  # 用户要求不能省略
        hostnames_str = "无" if not hostnames else "<br>".join(hostnames)
        
        # 使用简洁但完整的格式展示所有重要字段
        html += f'''
<br><strong style="color:#000000;">{ip}</strong><br>
<span style="color:#565656;">信誉评分: {confidence_score}% | 白名单: {is_whitelisted}</span><br>
<span style="color:#565656;">国家: {country_name} ({country_code}) | 用途类型: {usage_type}</span><br>
<span style="color:#565656;">ISP: {isp} | 域名: {domain}</span><br>
<span style="color:#565656;">总举报数: {total_reports} | 举报用户数: {num_distinct_users}</span><br>
<span style="color:#565656;">最后举报: {last_reported_at}</span><br>
<span style="color:#565656;">公网IP: {is_public} | IP版本: {ip_version} | Tor: {is_tor}</span><br>
<span style="color:#565656;">主机名: {hostnames_str}</span><br>
'''
        
        # 如果有详细报告，显示最新的几条
        if 'reports' in report and report['reports']:
            recent_reports = report['reports'][:3]  # 只显示最新3条
            html += '<span style="color:#aaaaaa; font-size:0.8rem;">最近举报:</span><br>'
            for i, r in enumerate(recent_reports, 1):
                report_time = r.get('reportedAt', '未知时间')[:10]  # 只显示日期部分
                comment = r.get('comment', '无描述')[:50]  # 限制长度
                if len(r.get('comment', '')) > 50:
                    comment += '...'
                categories = r.get('categories', [])
                categories_str = ', '.join(map(str, categories)) if categories else '未知'
                reporter_country = r.get('reporterCountryName', '未知')
                html += f'<span style="color:#aaaaaa; font-size:0.8rem;">{report_time}: {comment}</span><br>'
                html += f'<span style="color:#aaaaaa; font-size:0.8rem;">类别: {categories_str} | 举报者: {reporter_country}</span><br>'
            
            if len(report['reports']) > 3:
                html += f'<span style="color:#aaaaaa; font-size:0.8rem;">... 还有 {len(report["reports"]) - 3} 条举报</span><br>'
    
    # 闭合标签，与原模板结构保持一致
    html += '''</span></td>
                  </tr>
                </table>'''
    
    return html

def format_field_value(value) -> str:
    """格式化字段值"""
    if isinstance(value, bool):
        return "是" if value else "否"
    elif isinstance(value, list):
        if not value:
            return "无"
        return "<br>".join(str(item) for item in value)
    elif value is None:
        return "无"
    else:
        return str(value)

def generate_report_html(ban_ips: List[str], unban_ips: List[str], 
                        found_counter: Counter, start_time: datetime, 
                        end_time: datetime, abuseipdb_reports: Dict = None) -> str:
    """生成报告HTML"""
    
    # 尝试加载模板
    template = load_template('report-template.html')
    
    if not template:
        # 使用备用模板
        print("[WARN] 使用备用report模板")
        template = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Fail2Ban 报告</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .header { background-color: #f0f0f0; padding: 15px; border-radius: 5px; }
                .content { margin: 20px 0; }
                .section { margin: 15px 0; }
                .ip-list { background-color: #fafafa; padding: 10px; border-radius: 3px; }
            </style>
        </head>
        <body>
            <div class="header">
                <h2>$SUBJECT_PREFIX IP拦截报告</h2>
                <p>时间范围: $start – $end</p>
            </div>
            <div class="content">
                <div class="section">
                    <h3>Ban IP 数量: $ban_count</h3>
                    <div class="ip-list">$ban_ips</div>
                </div>
                <div class="section">
                    <h3>Unban IP 数量: $unban_count</h3>
                    <div class="ip-list">$unban_ips</div>
                </div>
                <div class="section">
                    <h3>失败尝试计数: $fail_count</h3>
                    <p>计数最高的 $TOP_N 个IP:</p>
                    <div class="ip-list">
                        <strong>次数:</strong><br>$top_fail_count<br><br>
                        <strong>IP地址:</strong><br>$top_fail_ips
                    </div>
                </div>
                $abuseipdb_section
            </div>
        </body>
        </html>
        """
    
    # 生成Ban IP列表 - 使用空格分隔，与原模板一致
    ban_list = " ".join(ban_ips) if ban_ips else "无"
    
    # 生成Unban IP列表 - 使用空格分隔，与原模板一致
    unban_list = " ".join(unban_ips) if unban_ips else "无"
    
    # 生成失败尝试Top N列表
    top_found = found_counter.most_common(TOP_N)
    top_fail_ips = "<br>".join([ip for ip, count in top_found]) if top_found else "无"
    top_fail_count = "<br>".join([str(count) for ip, count in top_found]) if top_found else "0"
    
    # 生成 AbuseIPDB 报告部分
    abuseipdb_section = ""
    if abuseipdb_reports:
        abuseipdb_section = format_abuseipdb_reports_html(abuseipdb_reports)
    
    # 准备变量字典
    variables = {
        'SUBJECT_PREFIX': SUBJECT_PREFIX,
        'start': start_time.strftime("%Y-%m-%d %H:%M:%S"),
        'end': end_time.strftime("%Y-%m-%d %H:%M:%S"),
        'ban_count': str(len(ban_ips)),
        'unban_count': str(len(unban_ips)),
        'ban_ips': ban_list,
        'unban_ips': unban_list,
        'fail_count': str(sum(found_counter.values())),
        'top_fail_ips': top_fail_ips,
        'top_fail_count': top_fail_count,
        'TOP_N': str(TOP_N),
        'abuseipdb_section': abuseipdb_section
    }
    
    # 使用统一的变量替换函数
    return replace_template_variables(template, variables)

def generate_status_html(status_info: Dict, start_time: datetime, end_time: datetime) -> str:
    """生成状态报告HTML"""
    
    # 尝试加载模板
    template = load_template('status-template.html')
    
    if not template:
        # 使用备用模板
        print("[WARN] 使用备用status模板")
        template = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Fail2Ban 状态报告</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .header { background-color: #f0f0f0; padding: 15px; border-radius: 5px; }
                .content { margin: 20px 0; }
                .status-box { background-color: #fafafa; padding: 15px; border-radius: 5px; border-left: 4px solid #007cba; }
                .status-normal { border-left-color: #28a745; }
                .status-error { border-left-color: #dc3545; }
            </style>
        </head>
        <body>
            <div class="header">
                <h2>$SUBJECT_PREFIX 服务状态报告</h2>
                <p>时间范围: $start - $end</p>
            </div>
            <div class="content">
                <div class="status-box">
                    <h3>$status_type</h3>
                    <p><strong>$log_file_status</strong></p>
                    <p>$status_detail</p>
                </div>
            </div>
        </body>
        </html>
        """
    
    # 准备变量字典
    variables = {
        'SUBJECT_PREFIX': SUBJECT_PREFIX,
        'start': start_time.strftime("%Y-%m-%d %H:%M:%S"),
        'end': end_time.strftime("%Y-%m-%d %H:%M:%S"),
        'status_type': status_info.get('status_message', ''),
        'log_file_status': status_info.get('log_file_status', ''),
        'status_detail': status_info.get('status_detail', '')
    }
    
    return replace_template_variables(template, variables)

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
        if SMTP_USER and SMTP_PASS:
            server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)

def send_email_resend(subject: str, html_body: str):
    """通过Resend API发送邮件"""
    if not requests:
        raise Exception("requests library is required for Resend API")
    
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

def send_email(subject: str, html_body: str, retry_queue: EmailRetryQueue = None):
    """发送邮件"""
    try:
        if MAIL_PROVIDER == "resend":
            send_email_resend(subject, html_body)
        else:
            send_email_smtp(subject, html_body)
        print(f"[INFO] 邮件发送成功: {subject}")
    except Exception as e:
        print(f"[ERROR] 邮件发送失败: {e}")
        
        # 如果启用了重试机制且提供了重试队列，将邮件加入队列
        if EMAIL_RETRY_ENABLED and retry_queue is not None:
            retry_queue.add_email(subject, html_body)

def main():
    """主函数"""
    print(f"[INFO] Fail2Ban Reporter 启动")
    print(f"[INFO] 日志路径: {LOG_PATH}")
    print(f"[INFO] 报告间隔: {INTERVAL_STR}")
    print(f"[INFO] 收集间隔: {COLLECT_INTERVAL}秒")
    print(f"[INFO] 邮件提供商: {MAIL_PROVIDER}")
    print(f"[INFO] 收件人: {', '.join(MAIL_TO)}")
    print(f"[INFO] 邮件重试: {'启用' if EMAIL_RETRY_ENABLED else '禁用'}")
    
    if EMAIL_RETRY_ENABLED:
        print(f"[INFO] 重试间隔: {EMAIL_RETRY_INTERVALS} 秒")
    
    if ABUSEIPDB_API_KEY:
        print(f"[INFO] AbuseIPDB API 已配置")
    else:
        print(f"[INFO] AbuseIPDB API 未配置")
    
    # 解析间隔
    try:
        interval_seconds = parse_interval(INTERVAL_STR)
        collect_interval_seconds = COLLECT_INTERVAL
    except ValueError as e:
        print(f"[ERROR] {e}")
        return
    
    # 初始化数据收集器
    collector = DataCollector(DATA_CACHE_PATH)
    
    # 初始化邮件重试队列
    retry_queue = None
    if EMAIL_RETRY_ENABLED:
        retry_queue = EmailRetryQueue(EMAIL_RETRY_CACHE_PATH)
    
    # 主循环
    while True:
        try:
            # 处理邮件重试队列
            if EMAIL_RETRY_ENABLED and retry_queue:
                retry_queue.process_retry_queue()
            
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
            
            # AbuseIPDB 查询逻辑
            abuseipdb_reports = {}
            abuseipdb_quota_insufficient = False
            
            if ABUSEIPDB_API_KEY and ban_ips:
                print("[INFO] 检测到 AbuseIPDB API 密钥，开始查询...")
                remaining_quota = check_abuseipdb_quota(ABUSEIPDB_API_KEY)
                
                if remaining_quota >= len(ban_ips):
                    print(f"[INFO] 开始查询 {len(ban_ips)} 个IP地址...")
                    for ip in ban_ips:
                        report = get_abuseipdb_report(ip, ABUSEIPDB_API_KEY)
                        if report:
                            abuseipdb_reports[ip] = report
                            print(f"[INFO] 成功获取 {ip} 的 AbuseIPDB 报告")
                        time.sleep(1)  # 遵循API使用礼仪，避免过快请求
                else:
                    print(f"[WARN] AbuseIPDB 查询额度不足，跳过查询。需要: {len(ban_ips)}, 剩余: {remaining_quota}")
                    abuseipdb_quota_insufficient = True
            
            # 检查日志文件状态（用于无内容状态汇报）
            log_status = collector.check_log_file_status(LOG_PATH, start_time, end_time)
            
            # 确定报告类型
            status_info = determine_status_type(len(ban_ips), len(unban_ips), 
                                              len(found_ips), log_status)
            
            # 生成报告和发送邮件
            if status_info['report_type'] == 'normal':
                # 正常报告（有事件）
                html_body = generate_report_html(ban_ips, unban_ips, found_counter, 
                                               start_time, end_time, abuseipdb_reports)
                subject = f"{SUBJECT_PREFIX} 报告 - {end_time.strftime('%Y-%m-%d %H:%M:%S')}"
                print(f"[INFO] 生成正常报告: Ban={len(ban_ips)}, Unban={len(unban_ips)}, Found={len(found_ips)}")
                if abuseipdb_reports:
                    print(f"[INFO] 包含 {len(abuseipdb_reports)} 个 AbuseIPDB 查询结果")
            else:
                # 状态报告（无事件）
                html_body = generate_status_html(status_info, start_time, end_time)
                if status_info['report_type'] == 'status_normal':
                    subject = f"{SUBJECT_PREFIX} 状态正常 - {end_time.strftime('%Y-%m-%d %H:%M:%S')}"
                    print(f"[INFO] 生成状态正常报告: 日志条目={log_status['total_lines']}")
                else:
                    subject = f"{SUBJECT_PREFIX} 状态异常 - {end_time.strftime('%Y-%m-%d %H:%M:%S')}"
                    print(f"[INFO] 生成状态异常报告: 无新日志条目")
            
            send_email(subject, html_body, retry_queue)
            
            # 如果 AbuseIPDB 额度不足，发送额外的通知邮件
            if abuseipdb_quota_insufficient:
                print("[INFO] 发送 AbuseIPDB 额度不足通知邮件...")
                quota_status_info = {
                    'status_message': 'AbuseIPDB 查询额度不足',
                    'log_file_status': 'API 额度状态',
                    'status_detail': f'AbuseIPDB API 每日查询额度不足。剩余额度: {remaining_quota}，但需要查询 {len(ban_ips)} 个IP地址。请考虑升级您的 AbuseIPDB 计划或等待额度重置。'
                }
                quota_html_body = generate_status_html(quota_status_info, start_time, end_time)
                quota_subject = f"{SUBJECT_PREFIX} 通知 - AbuseIPDB 额度不足 - {end_time.strftime('%Y-%m-%d %H:%M:%S')}"
                send_email(quota_subject, quota_html_body, retry_queue)
            
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

