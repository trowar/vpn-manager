#!/bin/sh
exec /opt/vpn-portal/.venv/bin/python /opt/vpn-portal/scripts/openvpn_auth.py "$1"
