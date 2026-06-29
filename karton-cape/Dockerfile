FROM python:3.12-alpine

LABEL maintainer="re-pipeline@security.local"
LABEL description="Karton CAPEv2 Intelligence Extractor"

# Install system dependencies
RUN apk add --no-cache git build-base libffi-dev

WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt /app/
RUN python3 -m venv /app/venv && \
    /app/venv/bin/pip install --upgrade pip && \
    /app/venv/bin/pip install --timeout 120 --retries 3 -r /app/requirements.txt

# Copy application
COPY karton-cape.py /app/karton-cape.py

ENV PATH="/app/venv/bin:$PATH"

CMD ["/app/venv/bin/python", "/app/karton-cape.py"]
