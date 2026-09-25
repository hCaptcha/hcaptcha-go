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

backend_dir=$(mktemp -d)
backend_pid=
cleanup() {
  if [ -n "$backend_pid" ]; then
    kill "$backend_pid" 2>/dev/null || true
    wait "$backend_pid" 2>/dev/null || true
  fi
  rm -rf "$backend_dir"
}
trap cleanup EXIT

go build -o "$backend_dir/backend" ./backend
"$backend_dir/backend" &
backend_pid=$!
npm run dev
