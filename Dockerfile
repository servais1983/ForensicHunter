# ForensicHunter Enterprise - Production Dockerfile
# Multi-stage build for optimized enterprise deployment

FROM ubuntu:22.04 as base

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV FORENSICHUNTER_ENV=production

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    build-essential \
    libssl-dev \
    libffi-dev \
    libjpeg-dev \
    zlib1g-dev \
    libpq-dev \
    postgresql-client \
    redis-tools \
    curl \
    wget \
    git \
    unzip \
    file \
    binutils \
    yara \
    volatility3 \
    && rm -rf /var/lib/apt/lists/*

# Create forensichunter user
RUN useradd --create-home --shell /bin/bash forensichunter

# Set working directory
WORKDIR /opt/forensichunter

# Copy requirements and install Python dependencies
COPY requirements-enterprise.txt .
RUN pip3 install --no-cache-dir -r requirements-enterprise.txt

# Development stage
FROM base as development

# Install development dependencies
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Change ownership
RUN chown -R forensichunter:forensichunter /opt/forensichunter

# Switch to forensichunter user
USER forensichunter

# Expose ports
EXPOSE 8000

# Development command
CMD ["python3", "-m", "uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

# Production stage
FROM base as production

# Install production-only dependencies
RUN pip3 install --no-cache-dir gunicorn

# Copy source code
COPY src/ ./src/
COPY config/ ./config/
COPY rules/ ./rules/
COPY setup.py .
COPY README.md .

# Install ForensicHunter
RUN pip3 install -e .

# Create directories
RUN mkdir -p /opt/forensichunter/evidence \
             /opt/forensichunter/reports \
             /opt/forensichunter/logs \
             /tmp/forensichunter

# Change ownership
RUN chown -R forensichunter:forensichunter /opt/forensichunter

# Switch to forensichunter user
USER forensichunter

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

# Expose ports
EXPOSE 8000 9090

# Production command
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "4", "--worker-class", "uvicorn.workers.UvicornWorker", "--access-logfile", "-", "--error-logfile", "-", "src.api.main:app"]