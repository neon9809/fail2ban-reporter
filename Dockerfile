FROM python:3.11-alpine

RUN adduser -D app && \
    apk add --no-cache tzdata ca-certificates && \
    pip install --no-cache-dir --upgrade pip && \
    mkdir -p /app/cache

WORKDIR /app

COPY app /app
RUN pip install --no-cache-dir -r requirements.txt


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


VOLUME ["/app/cache"]

CMD ["python", "/app/main.py"]