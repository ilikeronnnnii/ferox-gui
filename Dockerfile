# Ferox GUI — web dashboard for feroxbuster
FROM python:3.12-slim

# system deps: curl/unzip for the feroxbuster binary
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# feroxbuster (static release binary; pin the version for reproducible builds)
ARG FEROX_VERSION=2.13.1
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
        amd64) ferox_arch="x86_64" ;; \
        arm64) ferox_arch="aarch64" ;; \
        *) echo "unsupported arch: $arch" && exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/ferox.zip \
        "https://github.com/epi052/feroxbuster/releases/download/v${FEROX_VERSION}/${ferox_arch}-linux-feroxbuster.zip"; \
    unzip -o /tmp/ferox.zip -d /usr/local/bin; \
    chmod +x /usr/local/bin/feroxbuster; \
    rm /tmp/ferox.zip; \
    feroxbuster --version

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY wordlists ./wordlists

RUN mkdir -p /app/data/wordlists

ENV PYTHONUNBUFFERED=1
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD curl -fsS http://127.0.0.1:8000/api/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
