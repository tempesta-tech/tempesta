FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

ENV CONFIG=/etc/tempesta-ddos-defender/env
CMD python3 app.py
