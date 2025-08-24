# Fail2ban Reporter


一个可 **Docker 部署** 的极简工具：定时解析 `fail2ban.log`，统计本时段 `Ban / Unban / 失败尝试`，生成报告并通过 **SMTP** 或 **Resend Email API** 发送邮件。支持 **amd64 / arm64** 多架构镜像构建（GitHub Actions）。镜像基于 **python:3.11-alpine**，尽量小。



## 功能
- 定时（如：`3h5m`）扫描并统计 **过去 N 小时/分钟/秒** 的 fail2ban 日志窗口：
  - `Ban` 了多少个 IP（及 IP 列表）
  - `Unban` 了多少个 IP（及 IP 列表）
  - **失败尝试**（按 fail2ban 日志中的 `Found` 事件计数）
- 报告以纯文本邮件发送（可选 SMTP 或 Resend）。
- 容器里自动循环运行，无需外部 Cron。
- 多架构构建：`linux/amd64, linux/arm64`。

> 注：多数发行版里失败登录细节在 `auth.log` / `secure`，而 fail2ban 自身日志中会出现命中规则的 `Found` 事件。这里按 `Found` 计为“失败尝试”。

---

## 环境变量
| 变量 | 示例 | 说明 |
|---|---|---|
| `LOG_PATH` | `/var/log/fail2ban.log` | 挂载进容器的 fail2ban 日志路径 |
| `INTERVAL` | `3h5m` / `15m` / `1h` / `45s` | 定时周期；也用于计算每次扫描的时间窗口（*过去 INTERVAL 到现在*）|
| `MAIL_PROVIDER` | `smtp` / `resend` | 邮件发送方式 |
| `MAIL_TO` | `admin@domain.com,sec@domain.com` | 收件人，逗号分隔 |
| `SUBJECT_PREFIX` | `[Fail2Ban]` | 主题前缀，可选 |
| `TZ` | `Asia/Shanghai` | 容器时区（可选）|

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

### 直接 docker run
```bash
# 只读挂载 fail2ban.log 到容器
docker run -d --name f2b-reporter \
  -v /var/log/fail2ban.log:/var/log/fail2ban.log:ro \ # Linux默认fail2ban日志位置
  -e INTERVAL=3h5m \
  -e MAIL_PROVIDER=resend \
  -e RESEND_API_KEY=re_xxx \
  -e RESEND_FROM=no-reply@yourdomain.com \
  -e MAIL_TO=admin@domain.com,sec@domain.com \
  -e SUBJECT_PREFIX="[Fail2Ban]" \
  -e TZ=Asia/Shanghai \
  ghcr.io/neon9809/fail2ban-reporter:latest
```

### Apple Container
```bash
# 只读挂载 fail2ban.log 到容器
container run -d --name f2b-reporter \
  -v /var/log/fail2ban.log:/var/log/fail2ban.log:ro \ # 结合实际情况修改日志位置
  -e INTERVAL=3h5m \ 
  -e MAIL_PROVIDER=resend \
  -e RESEND_API_KEY=re_xxx \
  -e RESEND_FROM=no-reply@yourdomain.com \
  -e MAIL_TO=admin@domain.com,sec@domain.com \
  -e SUBJECT_PREFIX="[Fail2Ban]" \
  -e TZ=Asia/Shanghai \
  ghcr.io/neon9809/fail2ban-reporter:latest
```

### docker-compose.yml（可选）
```yaml
services:
  f2b-reporter:
    image: ghcr.io/neon9809/fail2ban-reporter:latest
    container_name: f2b-reporter
    environment:
      LOG_PATH: /var/log/fail2ban.log
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
    volumes:
      - /var/log/fail2ban.log:/var/log/fail2ban.log:ro
    restart: unless-stopped
```

---

## 说明与扩展
- **时间窗口**：每次运行会统计 *上一个 INTERVAL* 至当前时刻的日志，避免重复或错过（假设容器稳定按 INTERVAL 运行）。
- **IPv4/IPv6**：当前通过 `Ban ` / `Unban ` 后的第一个非空白字段捕获 IP/网段字符串，通常兼容 IPv6。
- **日志轮转**：默认仅读当前 `fail2ban.log`。
- **失败尝试计数**：这里以 fail2ban 的 `Found` 为“失败尝试”。
- **报表样式**：纯文本。


# Credits

本项目源代码主要由 [ChatGPT](https://chatgpt.com) 完成，[Perplexity AI](https://perplexity.ai)贡献了IP地址名单生成部分功能与部分代码解释。


