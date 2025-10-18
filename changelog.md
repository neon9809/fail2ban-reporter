# 邮件重试功能修改说明

## 修改概述

为 fail2ban-reporter 项目添加了邮件发送失败重试机制，当邮件发送失败时（如网络波动导致无法连接到 Resend API），系统会自动按照预设的时间间隔进行重试。

## 主要修改内容

### 1. 新增配置项

在文件开头添加了以下环境变量配置：

```python
# Email retry configuration
EMAIL_RETRY_ENABLED = os.getenv("EMAIL_RETRY", "false").lower() == "true"
EMAIL_RETRY_INTERVALS = [300, 600, 3600, 10800]  # 5分钟、10分钟、1小时、3小时（秒）
EMAIL_RETRY_CACHE_PATH = os.getenv("EMAIL_RETRY_CACHE_PATH", "/tmp/email_retry_queue.pkl")
```

**环境变量说明：**
- `EMAIL_RETRY`: 设置为 `true` 启用邮件重试功能，默认为 `false`
- `EMAIL_RETRY_CACHE_PATH`: 重试队列缓存文件路径（可选），默认为 `/tmp/email_retry_queue.pkl`

### 2. 新增 EmailRetryQueue 类

实现了一个完整的邮件重试队列管理类，包含以下功能：

- **队列持久化**：使用 pickle 将重试队列保存到文件，确保容器重启后队列不丢失
- **添加邮件到队列**：当邮件发送失败时，将邮件信息（主题、内容）加入队列
- **处理重试队列**：按照预设的时间间隔自动重试发送
- **智能重试管理**：
  - 第1次重试：失败后 5 分钟
  - 第2次重试：失败后 10 分钟
  - 第3次重试：失败后 1 小时
  - 第4次重试：失败后 3 小时
  - 重试成功后立即从队列移除
  - 达到最大重试次数后放弃并记录错误日志

### 3. 修改 send_email 函数

原函数只记录错误日志，修改后的函数会：

```python
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
```

### 4. 修改 main 函数

在主循环中添加了以下逻辑：

1. **初始化重试队列**：
   ```python
   retry_queue = None
   if EMAIL_RETRY_ENABLED:
       retry_queue = EmailRetryQueue(EMAIL_RETRY_CACHE_PATH)
   ```

2. **每次循环处理重试队列**：
   ```python
   # 处理邮件重试队列
   if EMAIL_RETRY_ENABLED and retry_queue:
       retry_queue.process_retry_queue()
   ```

3. **发送邮件时传入重试队列**：
   ```python
   send_email(subject, html_body, retry_queue)
   ```

## 使用方法

### Docker Compose 配置示例

```yaml
services:
  f2b-reporter:
    image: ghcr.io/neon9809/fail2ban-reporter:latest
    container_name: f2b-reporter
    restart: unless-stopped
    volumes:
      - /var/log:/fail2banTemp:ro
      - ./email_retry_queue:/tmp:rw  # 挂载重试队列缓存目录
    environment:
      LOG_PATH: /fail2banTemp/fail2ban.log
      INTERVAL: 3h
      TZ: Asia/Shanghai
      SUBJECT_PREFIX: "[F2B Report]"
      MAIL_TO: "your-email@example.com"
      MAIL_PROVIDER: resend
      RESEND_API_KEY: "re_your_api_key"
      RESEND_FROM: "Fail2ban Reporter <no-reply@yourdomain.com>"
      
      # 启用邮件重试功能
      EMAIL_RETRY: "true"
```

### Docker Run 命令示例

```bash
docker run -d --name f2b-reporter \
  --restart unless-stopped \
  -v /var/log:/fail2banTemp:ro \
  -v ./email_retry_queue:/tmp:rw \
  -e LOG_PATH=/fail2banTemp/fail2ban.log \
  -e INTERVAL=3h \
  -e MAIL_PROVIDER=resend \
  -e RESEND_API_KEY="re_your_api_key" \
  -e RESEND_FROM="Fail2ban Reporter <no-reply@yourdomain.com>" \
  -e MAIL_TO="your-email@example.com" \
  -e EMAIL_RETRY="true" \
  ghcr.io/neon9809/fail2ban-reporter:latest
```

## 工作流程

1. **邮件发送失败**：当首次发送邮件失败时（如网络波动），邮件会被加入重试队列
2. **自动重试**：程序在每次主循环开始时检查重试队列，如果有到达重试时间的邮件，则尝试发送
3. **重试成功**：一旦邮件发送成功，立即从队列中移除，不再重试
4. **重试失败**：如果重试仍然失败，根据当前重试次数计算下次重试时间
5. **达到上限**：如果已经重试 4 次仍然失败，记录错误日志并从队列移除

## 重试时间间隔

重试间隔采用递增策略，避免在短时间内频繁重试：

| 重试次数 | 时间间隔 | 累计等待时间 |
|---------|---------|-------------|
| 第1次   | 5分钟   | 5分钟       |
| 第2次   | 10分钟  | 15分钟      |
| 第3次   | 1小时   | 1小时15分钟 |
| 第4次   | 3小时   | 4小时15分钟 |

## 日志输出示例

### 邮件发送失败并加入队列
```
[ERROR] 邮件发送失败: HTTPSConnectionPool(host='api.resend.com', port=443): Max retries exceeded with url: /emails (Caused by NameResolutionError(...))
[INFO] 邮件已加入重试队列: [Fail2Ban] 报告 - 2025-10-18 12:00:00
```

### 重试发送邮件
```
[INFO] 重试发送邮件 (第1次): [Fail2Ban] 报告 - 2025-10-18 12:00:00
[INFO] 邮件重试发送成功: [Fail2Ban] 报告 - 2025-10-18 12:00:00
```

### 重试失败并计划下次重试
```
[INFO] 重试发送邮件 (第1次): [Fail2Ban] 报告 - 2025-10-18 12:00:00
[ERROR] 邮件重试发送失败 (第1次): HTTPSConnectionPool(...)
[INFO] 将在 600 秒后重试
```

### 达到最大重试次数
```
[ERROR] 邮件发送失败，已达到最大重试次数: [Fail2Ban] 报告 - 2025-10-18 12:00:00
```

## 注意事项

1. **重试间隔和次数固定**：按照用户要求，重试间隔和次数硬编码在代码中，不可通过环境变量修改
2. **队列持久化**：建议挂载 `/tmp` 目录以确保重试队列在容器重启后不丢失
3. **向后兼容**：如果不设置 `EMAIL_RETRY=true`，程序行为与原版完全一致
4. **适用场景**：主要用于解决临时网络波动导致的邮件发送失败问题
5. **SMTP 和 Resend 均支持**：重试机制对两种邮件发送方式都有效

## 文件变更

- **修改文件**：`app/main.py`
- **新增类**：`EmailRetryQueue`
- **修改函数**：`send_email()`, `main()`
- **新增配置**：`EMAIL_RETRY`, `EMAIL_RETRY_INTERVALS`, `EMAIL_RETRY_CACHE_PATH`

# Credit
本次更新由[Manus AI](https://manus.im)完成。