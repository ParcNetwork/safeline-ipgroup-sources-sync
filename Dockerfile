FROM python:3.12-slim

RUN apt-get update -y && apt-get install -y --no-install-recommends \
    ca-certificates curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd -m appuser
USER appuser

ENV STATE_PATH=.ipranges_state.json
ENV PYTHONUNBUFFERED=1

CMD ["python", "main.py"]