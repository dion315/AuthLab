# syntax=docker/dockerfile:1

# ---- build stage ------------------------------------------------------------
# SAML support (python3-saml) binds to the xmlsec1 C library, so the wheels for
# lxml and xmlsec must be built against the same libxml2 this image provides.
# Installing them with --no-binary is the reliable way to guarantee that; using
# the prebuilt wheels produces an "lxml & xmlsec libxml2 version mismatch"
# error at import time on some platform/version combinations.
FROM python:3.12-slim-bookworm AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install --no-install-recommends -y \
        build-essential \
        pkg-config \
        libxml2-dev \
        libxslt1-dev \
        libxmlsec1-dev \
        libxmlsec1-openssl \
        libssl-dev \
        libffi-dev \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /app
COPY pyproject.toml ./

RUN pip install --upgrade pip setuptools wheel \
    && pip install --no-binary lxml,xmlsec lxml xmlsec \
    && pip install ".[postgres]"

# ---- runtime stage ----------------------------------------------------------
FROM python:3.12-slim-bookworm AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH"

# Runtime shared libraries only — no compilers in the final image.
RUN apt-get update && apt-get install --no-install-recommends -y \
        libxml2 \
        libxmlsec1 \
        libxmlsec1-openssl \
        curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /opt/venv /opt/venv

WORKDIR /app
COPY app ./app

# Non-root, and a writable data directory for the default SQLite database.
RUN useradd --create-home --uid 10001 authlab \
    && mkdir -p /app/data \
    && chown -R authlab:authlab /app
USER authlab

EXPOSE 8000

# Liveness only: /healthz deliberately does not touch the database, so a brief
# database blip does not cause the platform to restart a healthy container.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://localhost:8000/healthz || exit 1

CMD ["python", "-m", "app.main"]
