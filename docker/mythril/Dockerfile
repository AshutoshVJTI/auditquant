FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        curl \
        git \
    && pip install --no-cache-dir mythril==0.23.15 solc-select==1.0.4 \
    && solc-select install 0.8.20 \
    && solc-select use 0.8.20 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
ENTRYPOINT ["myth"]
