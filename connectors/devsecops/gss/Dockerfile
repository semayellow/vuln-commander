FROM --platform=linux/amd64 ubuntu:latest

RUN apt-get update &&  \
    apt-get upgrade -y &&  \
    apt-get install -y git  \
    && apt install -y python3.12 \
    && apt install -y curl \
    && apt install -y nano

WORKDIR /vuln-commander

COPY sdk/ /vuln-commander/sdk
COPY shared/ /vuln-commander/shared
COPY connectors/devsecops/gss/ /vuln-commander/gss

WORKDIR /vuln-commander/sdk
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

RUN uv sync --locked

ENV PYTHONPATH=/vuln-commander

CMD ["uv", "run", "python", "../gss/main.py"]
