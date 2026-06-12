# ---------------------------------------------
# Stage 1: Node.js via NVM (build-only)
# ---------------------------------------------
FROM --platform=linux/amd64 ubuntu:24.04 AS node-builder

ENV NVM_DIR=/root/.nvm
ENV NODE_VERSION=22
ENV DEBIAN_FRONTEND=noninteractive

# Install NVM dependencies and Node.js
RUN apt-get update && apt-get install -y curl ca-certificates bash gnupg && \
    curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash && \
    . "$NVM_DIR/nvm.sh" && \
    nvm install $NODE_VERSION && \
    nvm alias default $NODE_VERSION && \
    nvm use default && \
    mkdir -p /node && \
    cp -r "$NVM_DIR" /node/nvm

# ---------------------------------------------
# Stage 2: Final App Image
# ---------------------------------------------
FROM --platform=linux/amd64 ubuntu:24.04

ENV NODE_VERSION=22
ENV NVM_DIR=/root/.nvm
ENV PATH="$NVM_DIR/versions/node/v$NODE_VERSION/bin:$PATH"

# Install system dependencies
RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    git \
    curl \
    nano \
    unzip \
    python3.12 \
    python3-venv \
    python3-setuptools \
    python3.12-dev \
    portaudio19-dev \
    ca-certificates \
    gnupg \
    bash \
    cmake \
    build-essential

# Copy full NVM installation from builder stage
COPY --from=node-builder /node/nvm /root/.nvm

# Set up automatic NVM sourcing in all bash sessions
RUN echo 'export NVM_DIR="$HOME/.nvm"' >> /root/.bashrc && \
    echo '[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"' >> /root/.bashrc && \
    echo 'export PATH="$NVM_DIR/versions/node/v'"$NODE_VERSION"'/bin:$PATH"' >> /root/.bashrc

# Set working directory
WORKDIR /vuln-commander

COPY sdk/ /vuln-commander/sdk
COPY shared/ /vuln-commander/shared
COPY connectors/devsecops/sca-license/ /vuln-commander/sca
COPY connectors/devsecops/install_scanner.sh /usr/local/bin/install-scanner

WORKDIR /vuln-commander/sdk
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

RUN uv sync --locked
RUN chmod +x /usr/local/bin/install-scanner

ENV PYTHONPATH=/vuln-commander

WORKDIR /vuln-commander

CMD ["bash", "-lc", "install-scanner trivy sca/scanner/trivy && sdk/.venv/bin/python sca/main.py"]
