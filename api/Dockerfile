FROM python:3.12-alpine

RUN apk add --no-cache postgresql-client

WORKDIR /vuln-commander

COPY api/ /vuln-commander/api
COPY shared/ /vuln-commander/shared
# After COPY api/, overlay sql_queries next to migrations (used by 5db404bd006e_initial).
COPY api/migrations/views_generation_spec /vuln-commander/api/views_generation_spec
COPY api/src/static /vuln-commander/api/src/static
COPY api/src/templates /vuln-commander/api/src/templates
COPY connectors/connectors_spec.yml /vuln-commander/connectors/connectors_spec.yml

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

ENV PYTHONPATH=/vuln-commander

RUN uv sync --project api --locked

RUN chmod +x /vuln-commander/api/docker-entrypoint.sh

ENTRYPOINT ["/vuln-commander/api/docker-entrypoint.sh"]
CMD ["uv", "run", "--project", "api", "uvicorn", "api.src.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
