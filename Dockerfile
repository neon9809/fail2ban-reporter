FROM python:3.11-alpine

# 让镜像更小：仅安装需要的包
RUN adduser -D app && \
    apk add --no-cache tzdata ca-certificates && \
    pip install --no-cache-dir --upgrade pip && \
    mkdir -p /app

WORKDIR /app
COPY app/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY app/main.py /app/main.py

USER app
ENV LOG_PATH=/var/log/fail2ban.log \
    INTERVAL=1h \
    MAIL_PROVIDER=smtp \
    TZ=UTC \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8

CMD ["python", "/app/main.py"]