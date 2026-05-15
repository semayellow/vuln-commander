FROM --platform=linux/amd64 ubuntu:latest

RUN apt-get update &&  \
    apt-get upgrade -y &&  \
    apt-get install -y git  \
    && apt install -y python3.12 \
    && apt install -y curl \
    && apt install -y nano \
    && apt install -y unzip
WORKDIR /vuln-commander

COPY sdk/ /vuln-commander/sdk
COPY shared/ /vuln-commander/shared
COPY connectors/devsecops/iac/ /vuln-commander/iac

WORKDIR /vuln-commander/sdk
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

RUN uv sync --locked
RUN unzip ../iac/kics.zip -d ../iac/ && rm ../iac/kics.zip

ENV PYTHONPATH=/vuln-commander

CMD ["uv", "run", "python", "../iac/main.py"]
