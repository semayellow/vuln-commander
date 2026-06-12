FROM --platform=linux/amd64 ubuntu:24.04

RUN apt-get update &&  \
    apt-get upgrade -y &&  \
    apt-get install -y git  \
    && apt install -y python3.12 \
    && apt install -y curl \
    && apt install -y ca-certificates \
    && apt install -y nano \
    && apt install -y unzip
WORKDIR /vuln-commander

COPY sdk/ /vuln-commander/sdk
COPY shared/ /vuln-commander/shared
COPY connectors/devsecops/iac/ /vuln-commander/iac
COPY connectors/devsecops/install_scanner.sh /usr/local/bin/install-scanner

WORKDIR /vuln-commander/sdk
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

RUN uv sync --locked
RUN chmod +x /usr/local/bin/install-scanner

ENV PYTHONPATH=/vuln-commander

WORKDIR /vuln-commander

CMD ["bash", "-lc", "install-scanner kics iac/scanner/kics iac/scanner/queries && sdk/.venv/bin/python iac/main.py"]
