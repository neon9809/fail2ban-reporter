## 本地/服务器运行
### ⚠️记得打开目录文件`/var/log/fail2ban.log`的读取权限

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
