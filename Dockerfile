FROM python:3.12-slim

RUN apt-get update -y && apt-get install -y --no-install-recommends \
    ca-certificates curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd -ms /bin/bash appuser
USER appuser

ENV STATE_PATH=.ipranges_state.json
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python3", "main.py"]