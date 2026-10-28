FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY piranha_backend_.py .
CMD ["sh", "-c", "uvicorn piranha_backend_:app --host 0.0.0.0 --proxy-headers --forwarded-allow-ips='*' --port ${PORT:-8000}"]
