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
        'last_entry_time': datetime  # 最后一条条目时间
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
