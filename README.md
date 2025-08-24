# fail2ban-reporter
一个可 Docker 部署 的极简工具：定时解析 fail2ban.log，统计本时段 Ban / Unban / 失败尝试，生成报告并通过 SMTP 或 Resend Email API 发送邮件。支持 amd64 / arm64 多架构镜像构建（GitHub Actions）。镜像基于 python:3.11-alpine，尽量小。源代码主要由ChatGPT完成。
