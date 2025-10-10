# Fail2ban Reporter

[![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/neon9809/fail2ban-reporter/docker-build.yml?branch=main&style=for-the-badge)](https://github.com/neon9809/fail2ban-reporter/actions) [![GitHub Container Registry](https://img.shields.io/badge/ghcr.io-fail2ban--reporter-blue?style=for-the-badge&logo=docker )](https://github.com/neon9809/fail2ban-reporter/pkgs/container/fail2ban-reporter ) [![License](https://img.shields.io/github/license/neon9809/fail2ban-reporter?style=for-the-badge)](https://github.com/neon9809/fail2ban-reporter/blob/main/LICENSE)

一个可 Docker 部署的极简工具：定时解析 `fail2ban.log`，统计指定时间窗口内的 `Ban` / `Unban` / `失败尝试` 事件，生成 HTML 报告并通过 SMTP 或 Resend API 发送邮件。

---

## 主要功能

- **定时报告**: 自动按预设的时间间隔（例如 `3h` 或 `15m`）扫描 `fail2ban.log`。
- **多维度统计**: 统计周期内的 IP **封禁 (Ban)**、**解封 (Unban)** 以及 **失败尝试 (Found)** 事件。
- **IP 信誉查询 (可选)**: 集成 [AbuseIPDB](https://www.abuseipdb.com/)，自动查询被封禁 IP 的信誉报告，并在邮件中展示详细信息。
- **智能状态报告**: 在没有事件的周期内，能够区分“服务正常但无事发生”和“日志读取异常”两种状态，并发送相应的状态邮件。
- **灵活的邮件发送**: 支持通过 **SMTP** 服务或 **[Resend.com](https://resend.com) API** 发送邮件。
- **多架构支持**: 通过 GitHub Actions 自动构建 `linux/amd64` 和 `linux/arm64` 架构的 Docker 镜像。
- **轻量级镜像**: 基于 `python:3.11-alpine` 构建，确保最小的资源占用。

## 运行方式

你可以通过 `docker run` 命令或 `docker-compose` 来部署 Fail2ban Reporter。

### 前提条件

请确保 Fail2ban 的日志目录 `/var/log` 对于 Docker 容器是可读的。**重要提示**：为了避免日志轮替后容器无法读取新文件的问题，我们需要挂载整个日志目录而不是单个文件。

```sh
# 确保日志目录可读
sudo chmod 755 /var/log
sudo chmod 644 /var/log/fail2ban.log
```

### 使用 `docker run`

以下是一个使用 Resend 发送邮件的示例：

```bash
docker run -d --name f2b-reporter \
  --restart unless-stopped \
  -v /var/log:/fail2banTemp:ro \
  -e LOG_PATH=/fail2banTemp/fail2ban.log \
  -e INTERVAL=3h \
  -e MAIL_PROVIDER=resend \
  -e RESEND_API_KEY="re_your_api_key" \
  -e RESEND_FROM="Fail2ban Reporter <no-reply@yourdomain.com>" \
  -e MAIL_TO="your-email@example.com" \
  -e SUBJECT_PREFIX="[F2B Report]" \
  -e TZ=Asia/Shanghai \
  -e ABUSEIPDB_API_KEY="your_abuseipdb_api_key" \
  ghcr.io/neon9809/fail2ban-reporter:latest
```

### 使用 `docker-compose.yml`

创建一个 `docker-compose.yml` 文件，内容如下：

```yaml
services:
  f2b-reporter:
    image: ghcr.io/neon9809/fail2ban-reporter:latest
    container_name: f2b-reporter
    restart: unless-stopped
    volumes:
      - /var/log:/fail2banTemp:ro
    environment:
      # --- 核心配置 ---
      LOG_PATH: /fail2banTemp/fail2ban.log
      INTERVAL: 3h
      TZ: Asia/Shanghai
      SUBJECT_PREFIX: "[F2B Report]"
      MAIL_TO: "your-email@example.com,another-admin@example.com"

      # --- 邮件发送方式 (选择一种) ---
      MAIL_PROVIDER: smtp # "smtp" 或 "resend"

      # --- SMTP 配置 ---
      SMTP_HOST: smtp.example.com
      SMTP_PORT: 587
      SMTP_USER: user@example.com
      SMTP_PASS: "your_smtp_password"
      SMTP_FROM: "Fail2ban Reporter <no-reply@example.com>"
      SMTP_TLS: "true"

      # --- Resend 配置 ---
      # RESEND_API_KEY: "re_your_api_key"
      # RESEND_FROM: "Fail2ban Reporter <no-reply@yourdomain.com>"

      # --- 可选功能 ---
      ABUSEIPDB_API_KEY: "your_abuseipdb_api_key" # 启用 AbuseIPDB 查询
      TOP_N: 10 # 在报告中显示失败尝试次数最多的 Top 10 IP
```

然后通过以下命令启动服务：

```sh
docker-compose up -d
```

## 配置说明

通过设置环境变量来配置此工具。

| 变量 | 示例 | 说明 |
|---|---|---|
| **`LOG_PATH`** | `/fail2banTemp/fail2ban.log` | **(必需)** 挂载到容器内的 fail2ban 日志路径。 |
| **`INTERVAL`** | `3h5m` / `15m` / `1h` | **(必需)** 报告周期。支持 `h`, `m`, `s` 组合。 |
| **`MAIL_PROVIDER`** | `smtp` / `resend` | **(必需)** 邮件发送方式。 |
| **`MAIL_TO`** | `admin@domain.com` | **(必需)** 收件人邮箱，多个地址用逗号分隔。 |
| `SUBJECT_PREFIX` | `[Fail2Ban]` | (可选) 邮件主题的前缀。 |
| `TZ` | `Asia/Shanghai` | (可选) 容器运行时区，用于正确显示报告时间。 |
| `TOP_N` | `10` | (可选) 报告中显示“失败尝试”最多的 IP 数量，默认为 `5`。 |
| `COLLECT_INTERVAL` | `300` | (可选) 日志收集器运行的周期（秒），用于处理日志轮转，默认为 `300`。 |
| `DATA_CACHE_PATH` | `/tmp/fail2ban_cache.pkl` | (可选) 用于存储日志扫描进度的缓存文件路径。 |

### AbuseIPDB 集成

| 变量 | 示例 | 说明 |
|---|---|---|
| `ABUSEIPDB_API_KEY` | `your_api_key` | (可选) 提供 AbuseIPDB 的 API 密钥以启用 IP 信誉查询功能。 |

### SMTP 配置

当 `MAIL_PROVIDER` 设置为 `smtp` 时，以下变量生效。

| 变量 | 示例 | 说明 |
|---|---|---|
| **`SMTP_HOST`** | `smtp.example.com` | **(必需)** SMTP 服务器地址。 |
| **`SMTP_PORT`** | `587` | **(必需)** SMTP 服务器端口。 |
| **`SMTP_USER`** | `user@example.com` | **(必需)** SMTP 用户名。 |
| **`SMTP_PASS`** | `your_password` | **(必需)** SMTP 密码或授权码。 |
| `SMTP_FROM` | `no-reply@example.com` | (可选) 发件人地址。如果未提供，将默认使用 `SMTP_USER`。 |
| `SMTP_TLS` | `true` | (可选) 是否启用 STARTTLS 加密，默认为 `true`。 |

### Resend.com 配置

当 `MAIL_PROVIDER` 设置为 `resend` 时，以下变量生效。

| 变量 | 示例 | 说明 |
|---|---|---|
| **`RESEND_API_KEY`** | `re_***` | **(必需)** Resend.com 的 API 密钥。 |
| **`RESEND_FROM`** | `no-reply@yourdomain.com` | **(必需)** 在 Resend.com 上已验证的发件人地址。 |

## 报告类型

工具会根据日志分析结果发送不同类型的邮件报告：

- **事件报告 (Normal Report)**: 当在时间窗口内检测到 `Ban`, `Unban`, 或 `Found` 事件时发送。报告中会包含详细的 IP 列表和统计数据。如果配置了 AbuseIPDB，还会附上 IP 信誉报告。

- **状态正常报告 (Status Normal Report)**: 当周期内没有任何事件，但日志文件仍在正常更新时发送。这表明 Fail2ban 服务在运行，只是没有新的封禁活动。

- **状态异常报告 (Status Error Report)**: 当周期内没有任何事件，且日志文件没有新内容时发送。这可能意味着 Fail2ban 服务或日志挂载存在问题，需要检查。

## 许可证

本项目基于 [MIT License](https://github.com/neon9809/fail2ban-reporter/blob/main/LICENSE) 开源。

## 致谢

本项目源代码主要由 [ChatGPT](https://chatgpt.com) 和[Perplexity AI](https://perplexity.ai)完成，[Manus AI](https://manus.im)完成了邮件通知的HTML支持以及两种无内容状态报告的功能以及AbuseIPDB查询与邮件报告的集成。[Claude AI](https://claude.ai) (Sonnet 4)完成了针对fail2ban日志轮转机制的内部缓存代码设计。

