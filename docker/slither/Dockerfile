# Bookworm: stable apt + libs. Unversioned -slim now tracks trixie, where apt's http helper
# can fail to exec on some Docker Desktop / arm64 setups ("Method http has died unexpectedly").
FROM python:3.10-slim-bookworm

# Solc compilers: `solc-select install` uses urllib and often gets HTTP 403 on list.json in CI/Docker.
# Use docker/prefetch_solc.py (browser-like User-Agent). Compose pins platform: linux/amd64 so
# all mapped versions exist (linux-arm64 only ships recent 0.8.x).
ARG TARGETARCH
ENV TARGETARCH=${TARGETARCH}
COPY docker/prefetch_solc.py /tmp/prefetch_solc.py
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        curl \
        git \
    && pip install --no-cache-dir slither-analyzer==0.9.0 solc-select==1.0.4 \
    && python3 /tmp/prefetch_solc.py && rm /tmp/prefetch_solc.py \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
ENTRYPOINT ["slither"]
