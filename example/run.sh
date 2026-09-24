#!/bin/sh
set -eu

cd "$(dirname "$0")"
if [ ! -f .env.local ]; then
  echo "Copy .env.local.example to .env.local and set credentials." >&2
  exit 1
fi

set -a
. ./.env.local
set +a

cleanup() {
  kill "$backend_pid" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

go run ./backend &
backend_pid=$!
npm run dev
