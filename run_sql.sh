#!/usr/bin/env bash
# Run SQL against the disposable Clerk + Supabase demo database.
# Credentials are sourced silently from clerk-supabase-demo.env and the
# password is supplied through PGPASSWORD rather than a command-line argument.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/clerk-supabase-demo.env"

usage() {
  cat >&2 <<'USAGE'
Usage:
  ./run_sql.sh -f path/to/query.sql
  ./run_sql.sh -q "SELECT now();"
  ./run_sql.sh -- [psql args...]
  ./run_sql.sh                         # interactive psql shell
USAGE
}

if [ ! -f "$ENV_FILE" ]; then
  echo "Error: $ENV_FILE not found" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$ENV_FILE"

DB_HOST="${SUPABASE_DB_HOST:-${host:-}}"
DB_PORT="${SUPABASE_DB_PORT:-${port:-5432}}"
DB_NAME="${SUPABASE_DB_NAME:-${database:-postgres}}"
DB_USER="${SUPABASE_DB_USER:-${user:-postgres}}"
DB_PASS="${SUPABASE_DB_PASSWORD:-}"

if [ -z "$DB_HOST" ] || [ -z "$DB_PASS" ]; then
  echo "Error: database host and password are required in $ENV_FILE" >&2
  exit 1
fi

if ! command -v psql >/dev/null 2>&1; then
  echo "Error: psql is not installed or not on PATH" >&2
  exit 1
fi

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

PSQL_ARGS=("-h" "$DB_HOST" "-p" "$DB_PORT" "-U" "$DB_USER" "-d" "$DB_NAME" "-v" "ON_ERROR_STOP=1" "-P" "pager=off")

case "${1:-}" in
  -f|--file)
    [ -n "${2:-}" ] || { echo "Error: $1 requires a file" >&2; exit 2; }
    [ -f "$2" ] || { echo "Error: SQL file not found: $2" >&2; exit 1; }
    exec env PGPASSWORD="$DB_PASS" PGSSLMODE="${PGSSLMODE:-require}" psql "${PSQL_ARGS[@]}" -f "$2"
    ;;
  -q|--query|-c)
    [ -n "${2:-}" ] || { echo "Error: $1 requires SQL" >&2; exit 2; }
    exec env PGPASSWORD="$DB_PASS" PGSSLMODE="${PGSSLMODE:-require}" psql "${PSQL_ARGS[@]}" -c "$2"
    ;;
  --)
    shift
    exec env PGPASSWORD="$DB_PASS" PGSSLMODE="${PGSSLMODE:-require}" psql "${PSQL_ARGS[@]}" "$@"
    ;;
  "")
    exec env PGPASSWORD="$DB_PASS" PGSSLMODE="${PGSSLMODE:-require}" psql "${PSQL_ARGS[@]}"
    ;;
  *)
    echo "Error: unknown option '$1'" >&2
    usage
    exit 2
    ;;
esac
