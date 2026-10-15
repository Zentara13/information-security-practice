# Dockerfile — security hardened (ЗПР-2)
FROM python:3.11-slim AS builder
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
COPY requirements.txt .
RUN pip install -r requirements.txt

FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH="/opt/venv/bin:$PATH"

# Non-root користувач без shell, фіксований UID
RUN groupadd -g 1000 appuser && \
    useradd -u 1000 -g appuser -d /app_code -s /usr/sbin/nologin appuser

WORKDIR /app_code
COPY --from=builder /opt/venv /opt/venv

# Код належить root -> appuser не може його змінити
COPY alembic.ini ./
COPY alembic ./alembic
COPY app ./app
COPY scripts ./scripts

# Писати можна лише в data/
RUN mkdir -p /app_code/data && chown appuser:appuser /app_code/data

USER appuser
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)" || exit 1

# Без --reload; --proxy-headers: реальний IP клієнта з X-Forwarded-For від Nginx
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--forwarded-allow-ips", "*"]
