FROM python:3.11-slim

# Install solc directly to avoid solc-select 403 errors in Docker/CI.
ARG TARGETARCH
RUN case "${TARGETARCH}" in \
    amd64) SOLC_VERSION="0.8.20+commit.a1b79de6"; SOLC_ARCH="amd64" ;; \
    arm64) SOLC_VERSION="0.8.31+commit.fd3a2265"; SOLC_ARCH="arm64" ;; \
    *) echo "Unsupported arch: ${TARGETARCH}"; exit 1 ;; \
    esac \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        curl \
        git \
    && pip install --no-cache-dir mythril==0.23.15 \
    && curl -fSL "https://binaries.soliditylang.org/linux-${SOLC_ARCH}/solc-linux-${SOLC_ARCH}-v${SOLC_VERSION}" -o /usr/local/bin/solc \
    && chmod +x /usr/local/bin/solc \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
ENTRYPOINT ["myth"]
