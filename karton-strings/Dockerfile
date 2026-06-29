FROM python:3.12-alpine

# Install system dependencies
RUN apk add --no-cache git build-base libffi-dev

WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt /app/
RUN python3 -m venv /app/venv && \
    /app/venv/bin/pip install --upgrade pip && \
    /app/venv/bin/pip install --timeout 120 --retries 3 -r /app/requirements.txt

# Copy application
COPY karton-strings.py /app/karton-strings.py

ENV PATH="/app/venv/bin:$PATH"

CMD ["/app/venv/bin/python", "/app/karton-strings.py"]
