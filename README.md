# Fail2ban Reporter

一个可 **Docker 部署** 的极简工具：定时解析 `fail2ban.log`，统计本时段 `Ban / Unban / 失败尝试`，生成报告并通过 **SMTP** 或 **Resend Email API** 发送邮件。支持 **amd64 / arm64** 多架构镜像构建（GitHub Actions）。镜像基于 **python:3.11-alpine**，尽量小。

## 新功能：AbuseIPDB 集成

- **IP 信誉查询**: 可选配置 AbuseIPDB API 密钥，自动查询被封禁 IP 的信誉详情。
- **智能额度管理**: 查询前自动检查 API 剩余额度，额度不足时将发送邮件通知。
- **丰富报告内容**: 将 AbuseIPDB 的查询结果以表格形式完整呈现在邮件报告中。

## 功能
- 定时（如：`3h5m`）扫描并统计 **过去 N 小时/分钟/秒** 的 fail2ban 日志窗口：
  - `Ban` 了多少个 IP（及 IP 列表）
  - `Unban` 了多少个 IP（及 IP 列表）
  - **失败尝试**（按 fail2ban 日志中的 `Found` 事件计数）
- 报告以HTML邮件发送（可选 SMTP 或 Resend）。
- 容器里自动循环运行，无需外部 Cron。
- 多架构构建：`linux/amd64, linux/arm64`。

> 注：多数发行版里失败登录细节在 `auth.log` / `secure`，而 fail2ban 自身日志中会出现命中规则的 `Found` 事件。这里按 `Found` 计为“失败尝试”。

---

## 环境变量
| 变量 | 示例 | 说明 |
|---|---|---|
| `LOG_PATH` | `/f2btemp/fail2ban.log` | 挂载进容器的 fail2ban 日志路径 |
| `INTERVAL` | `3h5m` / `15m` / `1h` / `45s` | 定时周期；也用于计算每次扫描的时间窗口（*过去 INTERVAL 到现在*）|
| `COLLECT_INTERVAL` | `300` | 日志收集周期；默认300，单位秒，以防止fail2ban日志轮转后读取异常 |
| `MAIL_PROVIDER` | `smtp` / `resend` | 邮件发送方式 |
| `MAIL_TO` | `admin@domain.com,sec@domain.com` | 收件人，逗号分隔 |
| `SUBJECT_PREFIX` | `[Fail2Ban]` | 主题前缀，可选 |
| `TZ` | `Asia/Shanghai` | 容器时区（可选）|
| `TOP_N` | `5` | 报告失败尝试次数最多的IP地址数量 默认报告失败尝试次数最多的5个IP地址（可选）|
| `ABUSEIPDB_API_KEY` | `your_api_key` | (可选) AbuseIPDB 的 API 密钥。如果提供，将查询被封禁 IP 的信誉信息。 |

**[邮件内容样式](https://github.com/neon9809/fail2ban-reporter/blob/main/app/report-template.html)**

**SMTP 模式**
| 变量 | 示例 | 说明 |
|---|---|---|
| `SMTP_HOST` | `smtp.example.com` | SMTP 服务器 |
| `SMTP_PORT` | `587` | 端口 |
| `SMTP_USER` | `user@example.com` | 用户名 |
| `SMTP_PASS` | `***` | 密码/授权码 |
| `SMTP_TLS` | `true` | 是否 STARTTLS；如走 465 可设为 `false` 并改用 SSL（见代码自动判断）|
| `SMTP_FROM` | `no-reply@example.com` | 发件人 |

**Resend 模式**（https://resend.com）
| 变量 | 示例 | 说明 |
|---|---|---|
| `RESEND_API_KEY` | `re_***` | Resend API Key |
| `RESEND_FROM` | `no-reply@yourdomain.com` | Verified sender（需在 Resend 验证）|

---


## 本地/服务器运行
### ⚠️记得打开目录文件`/var/log/fail2ban.log`的读取权限

### 直接 docker run
```bash
# 只读挂载 fail2ban.log 到容器
docker run -d --name f2b-reporter \
  -v /var/log:/f2btemp:ro \
  -e INTERVAL=3h5m \
  -e LOG_PATH=/f2btemp/fail2ban.log \
  -e MAIL_PROVIDER=resend \
  -e RESEND_API_KEY=re_xxx \
  -e RESEND_FROM=no-reply@yourdomain.com \
  -e MAIL_TO=admin@domain.com,sec@domain.com \
  -e SUBJECT_PREFIX="[Fail2Ban]" \
  -e TZ=Asia/Shanghai \
  -e ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here \
  ghcr.io/neon9809/fail2ban-reporter:latest
```

### docker-compose.yml（可选）
```yaml
services:
  f2b-reporter:
    image: ghcr.io/neon9809/fail2ban-reporter:latest
    container_name: f2b-reporter
    environment:
      LOG_PATH: /f2btemp/fail2ban.log
      INTERVAL: 3h5m
      MAIL_PROVIDER: smtp  # 或 resend
      SMTP_HOST: smtp.example.com
      SMTP_PORT: 587
      SMTP_USER: user@example.com
      SMTP_PASS: yourpass
      SMTP_TLS: "true"
      SMTP_FROM: no-reply@example.com
      MAIL_TO: admin@domain.com,sec@domain.com
      SUBJECT_PREFIX: "[Fail2Ban]"
      TZ: Asia/Shanghai
      ABUSEIPDB_API_KEY: your_abuseipdb_api_key_here # 可选
    volumes:
      - /var/log:/f2btemp:ro
    restart: unless-stopped
```

---

## 说明与扩展
- **时间窗口**：每次运行会统计 *上一个 INTERVAL* 至当前时刻的日志，避免重复或错过（假设容器稳定按 INTERVAL 运行）。
- **IPv4/IPv6**：当前通过 `Ban ` / `Unban ` 后的第一个非空白字段捕获 IP/网段字符串，通常兼容 IPv6。
- **日志轮转**：默认仅读当前 `fail2ban.log`。
- **失败尝试计数**：这里以 fail2ban 的 `Found` 为“失败尝试”。

# Fail2ban Reporter 无内容状态汇报功能

## 功能概述

为fail2ban-reporter项目添加了**无内容状态汇报功能**，当在一个INTERVAL周期内没有Ban/Unban/失败尝试内容时，系统会自动检查日志文件状态并发送相应的状态报告邮件。

## 功能特性

### 1. 智能状态检测
- **有事件时**：正常发送包含Ban/Unban/失败尝试统计的报告
- **无事件但有日志时**：发送"服务状态正常"报告
- **无事件且无日志时**：发送"服务状态异常"报告

### 2. 日志文件状态检查
- 检查指定时间窗口（INTERVAL周期）内的日志文件更新情况
- 统计新增日志条目数量
- 记录最后一条日志的时间戳

### 3. 状态报告类型

#### 正常报告（有事件）
- **触发条件**：检测到Ban/Unban/Found事件
- **使用模板**：`report-template.html`
- **邮件主题**：`[Fail2Ban] 报告 - 时间戳`
- **内容**：包含详细的IP统计信息

#### 状态正常报告（无事件但有日志）
- **触发条件**：无Ban/Unban/Found事件，但日志文件有新条目
- **使用模板**：`status-template.html`
- **邮件主题**：`[Fail2Ban] 状态正常 - 时间戳`
- **状态信息**：
  - 状态类型：服务状态正常
  - 日志文件状态：日志文件正常
  - 详细信息：没有发现新的拦截内容（检查了 N 条日志记录）

#### 状态异常报告（无事件且无日志）
- **触发条件**：无Ban/Unban/Found事件，且日志文件无新条目
- **使用模板**：`status-template.html`
- **邮件主题**：`[Fail2Ban] 状态异常 - 时间戳`
- **状态信息**：
  - 状态类型：服务状态异常
  - 日志文件状态：日志文件没有新内容
  - 详细信息：请检查容器访问日志文件fail2ban.log的相关配置

## 技术实现

### 1. 新增方法

#### `DataCollector.check_log_file_status()`
```python
def check_log_file_status(self, log_path: str, start_time: datetime, end_time: datetime) -> Dict:
    """
    检查日志文件在指定时间窗口内的状态
    返回：
    {
        'has_new_entries': bool,  # 是否有新条目
        'total_lines': int,       # 新条目总数
        'last_entry_time
': datetime  # 最后一条条目时间
    }
    """
```

#### `determine_status_type()`
```python
def determine_status_type(ban_count: int, unban_count: int, found_count: int, 
                         log_status: Dict) -> Dict:
    """
    根据事件数量和日志状态确定报告类型
    返回报告类型和状态信息
    """
```

#### `generate_status_html()`
```python
def generate_status_html(status_info: Dict, start_time: datetime, end_time: datetime) -> str:
    """
    生成状态报告HTML，使用status-template.html模板
    """
```

### 2. 主循环逻辑增强

```python
# 检查日志文件状态（用于无内容状态汇报）
log_status = collector.check_log_file_status(LOG_PATH, start_time, end_time)

# 确定报告类型
status_info = determine_status_type(len(ban_ips), len(unban_ips), 
                                  len(found_ips), log_status)

# 根据报告类型生成相应的HTML和邮件主题
if status_info['report_type'] == 'normal':
    # 正常报告
    html_body = generate_report_html(...)
    subject = f"{SUBJECT_PREFIX} 报告 - {timestamp}"
else:
    # 状态报告
    html_body = generate_status_html(...)
    subject = f"{SUBJECT_PREFIX} 状态正常/异常 - {timestamp}"
```

## 配置要求

### 环境变量
无需新增环境变量，使用现有配置：
- `INTERVAL`：报告周期，也是状态检查的时间窗口
- `LOG_PATH`：fail2ban.log文件路径
- `SUBJECT_PREFIX`：邮件主题前缀

### 模板文件
- `report-template.html`：正常报告模板（现有）
- `status-template.html`：状态报告模板（现有）

## 使用示例

### Docker运行
```bash
docker run -d --name f2b-reporter \
  -v /var/log:/f2btemp:ro \
  -e INTERVAL=3h5m \
  -e LOG_PATH=/f2btemp/fail2ban.log \
  -e MAIL_PROVIDER=smtp \
  -e SMTP_HOST=smtp.example.com \
  -e SMTP_PORT=587 \
  -e SMTP_USER=user@example.com \
  -e SMTP_PASS=password \
  -e SMTP_FROM=no-reply@example.com \
  -e MAIL_TO=admin@domain.com \
  -e SUBJECT_PREFIX="[Fail2Ban]" \
  ghcr.io/neon9809/fail2ban-reporter:latest
```

### 预期行为
1. **正常情况**：每3小时5分钟发送一次报告
2. **有事件时**：发送包含Ban/Unban/失败尝试统计的详细报告
3. **无事件但服务正常**：发送"服务状态正常"的简洁报告
4. **服务异常**：发送"服务状态异常"的警告报告

## 向后兼容性

- 完全兼容现有功能和配置
- 不影响现有的正常报告逻辑
- 仅在无事件时才触发状态检查和报告

## 测试验证

已通过以下场景的测试：
1. ✅ 有Ban/Unban/Found事件 → 正常报告
2. ✅ 无事件但有日志条目 → 状态正常报告
3. ✅ 无事件且无日志条目 → 状态异常报告

所有测试场景均能正确生成相应的HTML邮件报告。

# Credits

本项目源代码主要由 [ChatGPT](https://chatgpt.com) 完成，[Perplexity AI](https://perplexity.ai)贡献了IP地址名单生成部分功能与部分代码解释，在[Manus AI](https://manus.ai)的协助下添加了邮件通知的HTML支持。[Claude AI](https://claude.ai) (Sonnet 4)完成了针对fail2ban日志轮转机制的内部缓存代码设计。

