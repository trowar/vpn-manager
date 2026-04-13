#!/usr/bin/env bash
set -euo pipefail

if [ "${PORTAL_ENABLE_UDP_RELAY:-0}" = "1" ]; then
  python /app/scripts/udp_relay.py &
fi

exec gunicorn --workers 2 --bind 0.0.0.0:8080 wsgi:app
