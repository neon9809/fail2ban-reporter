FROM python:3.11-alpine

# 让镜像更小：仅安装必要的包
RUN adduser -D app && \
    apk add --no-cache tzdata ca-certificates && \
    pip install --no-cache-dir --upgrade pip && \
    mkdir -p /app/cache

WORKDIR /app

COPY app/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY app/main.py /app/main.py
COPY app/report-template.html /app/report-template.html

# 修复：确保 app 用户拥有缓存目录的权限
RUN chown -R app:app /app && chmod -R 755 /app/cache

USER app

ENV LOG_PATH=/var/log/fail2ban.log \
    INTERVAL=1h \
    COLLECT_INTERVAL=300 \
    DATA_CACHE_PATH=/app/cache/fail2ban_cache.pkl \
    MAIL_PROVIDER=smtp \
    TZ=UTC \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8

# 创建音量挂载点用于持久化缓存
VOLUME ["/app/cache"]

CMD ["python", "/app/main.py"]