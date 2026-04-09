FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    wireguard-tools \
    openvpn \
    dnsmasq \
    iptables \
    iproute2 \
    kmod \
    procps \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/vpn-service

RUN pip install --upgrade pip && pip install Flask==3.0.3 gunicorn==22.0.0 werkzeug==3.0.2

COPY docker/vpn/vpn_api.py /opt/vpn-service/vpn_api.py
COPY docker/vpn/entrypoint.sh /opt/vpn-service/entrypoint.sh
COPY scripts/openvpn_auth.py /opt/vpn-service/openvpn_auth.py

RUN chmod +x /opt/vpn-service/entrypoint.sh /opt/vpn-service/openvpn_auth.py

EXPOSE 8081 51820/udp 1194/udp 53/udp 53/tcp

ENTRYPOINT ["/opt/vpn-service/entrypoint.sh"]
