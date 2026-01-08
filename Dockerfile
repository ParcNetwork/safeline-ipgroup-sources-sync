FROM python:3.12-slim-bookworm

ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
ENV PYTHONUNBUFFERED=1
ENV STATE_PATH=.ipranges_state.json

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN python -m playwright install-deps

RUN python -m playwright install chromium

COPY . .

RUN useradd -ms /bin/bash appuser
USER appuser

ENTRYPOINT ["python3", "main.py"]