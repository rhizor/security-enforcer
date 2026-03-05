# Security-Enforcer - Dockerized Test Environment

FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -s /bin/bash appuser

# Copy requirements and install dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Install test dependencies
RUN pip install --no-cache-dir pytest pytest-cov

# Copy project files
COPY enforcer.py ./
COPY orchestrator.py ./
COPY enforcerctl ./
COPY tests/ ./tests/
COPY pytest.ini ./

# Set ownership
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

ENV PYTHONPATH=/app

CMD ["pytest", "-v", "--tb=short"]
