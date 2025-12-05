# Oyente Symbolic Executor Docker Image
# https://github.com/enzymefinance/oyente
FROM python:3.8-slim

# Install dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    wget \
    software-properties-common \
    && rm -rf /var/lib/apt/lists/*

# Install solc 0.4.25 (Oyente works best with older Solidity)
RUN wget https://github.com/ethereum/solidity/releases/download/v0.4.25/solc-static-linux \
    -O /usr/local/bin/solc-0.4.25 && chmod +x /usr/local/bin/solc-0.4.25 && \
    ln -s /usr/local/bin/solc-0.4.25 /usr/local/bin/solc

# Install Go-Ethereum (for EVM)
RUN curl -fsSL https://gethstore.blob.core.windows.net/builds/geth-linux-amd64-1.10.26-e5eb32ac.tar.gz \
    | tar -xz -C /usr/local/bin --strip-components=1

# Install Z3 theorem prover
RUN pip install --no-cache-dir z3-solver

# Clone and install Oyente
WORKDIR /opt
RUN git clone https://github.com/enzymefinance/oyente.git && \
    cd oyente && \
    pip install --no-cache-dir -r requirements.txt

WORKDIR /work

ENTRYPOINT ["python", "/opt/oyente/oyente/oyente.py"]
