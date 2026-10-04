FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd -m -u 10001 app
COPY app ./app
USER app
ENV PYTHONUNBUFFERED=1
EXPOSE 8000
