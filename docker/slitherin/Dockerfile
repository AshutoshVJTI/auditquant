FROM python:3.10-slim-bookworm

ARG TARGETARCH
ENV TARGETARCH=${TARGETARCH}
COPY docker/prefetch_solc.py /tmp/prefetch_solc.py
COPY docker/slitherin/deflat_tokens.json /tmp/deflat_tokens.json
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        curl \
        git \
    && pip install --no-cache-dir slither-analyzer==0.9.0 solc-select==1.0.4 slitherin \
    && DEST=$(python3 -c "import pathlib, slither_pess; print(pathlib.Path(slither_pess.__file__).resolve().parent / 'utils' / 'deflat_tokens.json')") \
    && mkdir -p "$(dirname "$DEST")" \
    && cp /tmp/deflat_tokens.json "$DEST" \
    && rm /tmp/deflat_tokens.json \
    && python3 /tmp/prefetch_solc.py && rm /tmp/prefetch_solc.py \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
ENTRYPOINT ["slither"]
