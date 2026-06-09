# ForensicHunter — Multi-stage production Dockerfile
# Stage 1: base system with OS-level dependencies
FROM ubuntu:22.04 AS base

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    FORENSICHUNTER_ENV=production \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-dev \
    build-essential \
    libssl-dev \
    libffi-dev \
    libjpeg-dev \
    zlib1g-dev \
    curl \
    wget \
    file \
    binutils \
    yara \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash forensichunter

WORKDIR /opt/forensichunter

# ----------------------------------------------------------------
# Stage 2: development
# ----------------------------------------------------------------
FROM base AS development

COPY requirements.txt requirements-prod.txt ./
RUN pip3 install -r requirements.txt -r requirements-prod.txt

COPY . .

RUN mkdir -p evidence reports logs config \
    && chown -R forensichunter:forensichunter /opt/forensichunter

USER forensichunter
EXPOSE 8000
CMD ["python3", "-m", "uvicorn", "src.api.main:app", \
     "--host", "0.0.0.0", "--port", "8000", "--reload"]

# ----------------------------------------------------------------
# Stage 3: production
# ----------------------------------------------------------------
FROM base AS production

COPY requirements-prod.txt ./
RUN pip3 install -r requirements-prod.txt gunicorn

COPY src/     ./src/
COPY rules/   ./rules/
COPY static/  ./static/
COPY setup.py README.md ./

# Create runtime directories (config holds non-secret runtime config)
RUN mkdir -p evidence reports logs config \
    && pip3 install -e . \
    && chown -R forensichunter:forensichunter /opt/forensichunter

USER forensichunter

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -sf http://localhost:8000/api/health || exit 1

EXPOSE 8000

CMD ["gunicorn", \
     "--bind", "0.0.0.0:8000", \
     "--workers", "4", \
     "--worker-class", "uvicorn.workers.UvicornWorker", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "--timeout", "120", \
     "src.api.main:app"]
