# Oyente Symbolic Executor Docker Image
# https://github.com/enzymefinance/oyente
FROM python:3.8-slim

# Reduce pip noise and avoid caching large layers
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# Install dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    wget \
    software-properties-common \
    ca-certificates \
    libgcc-s1 \
    libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

# Ensure modern pip tooling (better wheel selection)
RUN python -m pip install --upgrade pip setuptools wheel

# Install solc 0.4.25 (Oyente works best with older Solidity)
RUN wget https://github.com/ethereum/solidity/releases/download/v0.4.25/solc-static-linux \
    -O /usr/local/bin/solc-0.4.25 && chmod +x /usr/local/bin/solc-0.4.25 && \
    ln -s /usr/local/bin/solc-0.4.25 /usr/local/bin/solc

# Install Go-Ethereum (for EVM)
RUN curl -fsSL https://gethstore.blob.core.windows.net/builds/geth-linux-amd64-1.10.26-e5eb32ac.tar.gz \
    | tar -xz -C /usr/local/bin --strip-components=1

# Install Z3 theorem prover
RUN python -m pip install --only-binary=:all: "z3-solver==4.12.2.0"

# Clone and install Oyente v0.2.7 (use setup.py, there is no requirements.txt at repo root)
WORKDIR /opt
RUN git clone https://github.com/enzymefinance/oyente.git && \
    cd oyente && \
    git checkout 0.2.7 && \
    python -m pip install --no-cache-dir .

WORKDIR /work

ENTRYPOINT ["python", "-m", "oyente.oyente"]
