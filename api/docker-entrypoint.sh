#!/bin/sh
set -e

POSTGRESQL_HOST="${POSTGRESQL_HOST:-db}"
POSTGRESQL_PORT_NUMBER="${POSTGRESQL_PORT_NUMBER:-5432}"
POSTGRESQL_USERNAME="${POSTGRESQL_USERNAME:-postgres}"

echo "Waiting for PostgreSQL at ${POSTGRESQL_HOST}:${POSTGRESQL_PORT_NUMBER}..."
until pg_isready -h "$POSTGRESQL_HOST" -p "$POSTGRESQL_PORT_NUMBER" -U "$POSTGRESQL_USERNAME" >/dev/null 2>&1; do
  sleep 1
done

echo "Running database migrations..."
uv run --project api alembic -c api/alembic.ini upgrade head

echo "Creating admin and connectors accounts..."
uv run --project api python -m api.src.core.orm.initialisation.session

exec "$@"
