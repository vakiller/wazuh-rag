# Multi-stage Dockerfile for RAG Wazuh System
FROM python:3.11-slim as base

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    cron \
    ca-certificates \
    curl \
    postgresql-client \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Create application directory
WORKDIR /app

# Copy requirements first for better layer caching
COPY requirements.txt .

# Install Python dependencies with increased timeout and retries
# Split into phases to handle large packages like PyTorch
RUN pip install --default-timeout=1000 --retries 5 \
    opensearch-py==2.3.1 \
    apscheduler==3.10.4 \
    requests>=2.31.0 \
    psycopg2-binary>=2.9.9 \
    python-dotenv==1.0.0 \
    pyyaml>=6.0.1

# Install transformers and dependencies (these are large)
RUN pip install --default-timeout=1000 --retries 5 \
    Pillow>=12.0.0 \
    torch>=2.9.0 \
    transformers==4.57.1

# Install sentence-transformers and remaining packages
RUN pip install --default-timeout=1000 --retries 5 \
    sentence-transformers==5.1.2 \
    faiss-cpu>=1.7.4 \
    numpy>=1.24.0 \
    'urllib3>=1.26.0,<2.0.0' \
    langchain-ollama>=0.1.0 \
    langchain-community>=0.3.0 \
    langchain-core>=0.3.0

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /app/data/faiss_index \
    /app/logs \
    /app/collected_alerts \
    /var/log/cron

# Copy cron configuration
COPY docker/crontab /etc/cron.d/wazuh-cron
RUN chmod 0644 /etc/cron.d/wazuh-cron && \
    crontab /etc/cron.d/wazuh-cron

# Copy entrypoint script
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Create log file for cron
RUN touch /var/log/cron/cron.log

# Expose no ports (this is a background service)

# Health check
HEALTHCHECK --interval=5m --timeout=10s --start-period=30s --retries=3 \
    CMD python -c "import psycopg2; psycopg2.connect(host='${DB_HOST}', port='${DB_PORT}', database='${DB_NAME}', user='${DB_USER}', password='${DB_PASSWORD}')" || exit 1

# Set entrypoint
ENTRYPOINT ["/entrypoint.sh"]

# Default command - run cron in foreground
CMD ["cron", "-f"]
