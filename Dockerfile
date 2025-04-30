# syntax=docker/dockerfile:1
FROM python:3.13-slim-bullseye

# Create a non-root user
RUN useradd -m -u 1000 appuser

# Install system dependencies including OpenSSL
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libssl-dev build-essential \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app .

# Set ownership to non-root user
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Run the application
CMD ["python", "-u", "app.py"]