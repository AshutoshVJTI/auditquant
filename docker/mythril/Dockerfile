FROM python:3.10-slim-bookworm

# Pin z3-solver: 4.13+ often falls back to building Z3 from source, which needs GCC 13+
# (C++20 <format>). Debian bookworm ships GCC 12 - use a release that ships manylinux wheels.
ARG TARGETARCH
ENV TARGETARCH=${TARGETARCH}
COPY docker/prefetch_solc.py /tmp/prefetch_solc.py
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        curl \
        git \
    && pip install --no-cache-dir \
        --only-binary=z3-solver \
        "z3-solver==4.12.2.0" \
        "mythril==0.23.15" \
        "solc-select==1.0.4" \
    && python3 /tmp/prefetch_solc.py && rm /tmp/prefetch_solc.py \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
ENTRYPOINT ["myth"]
