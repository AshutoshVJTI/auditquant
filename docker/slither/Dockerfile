FROM python:3.10-slim

# Install solc directly (solc-select often gets 403 when fetching version list in Docker/CI).
# amd64: 0.8.20; arm64: 0.8.31 (0.8.20 not published for arm64 on binaries.soliditylang.org).
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
    && pip install --no-cache-dir slither-analyzer==0.9.0 solc-select==1.0.4 \
    && curl -fSL "https://binaries.soliditylang.org/linux-${SOLC_ARCH}/solc-linux-${SOLC_ARCH}-v${SOLC_VERSION}" -o /usr/local/bin/solc \
    && chmod +x /usr/local/bin/solc \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
ENTRYPOINT ["slither"]
