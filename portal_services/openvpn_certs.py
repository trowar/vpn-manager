import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from portal_auth import row_get
from portal_config import (
    OPENVPN_CLIENT_CERT_RENEW_BEFORE_DAYS,
    OPENVPN_CLIENT_CERT_VALID_DAYS,
    OPENVPN_COMMON_NAME_PREFIX,
    SHARED_OPENVPN_CA_CERT_FILE,
    SHARED_OPENVPN_CA_KEY_FILE,
    SHARED_OPENVPN_SERVER_CERT_FILE,
    SHARED_OPENVPN_SERVER_KEY_FILE,
    SHARED_OPENVPN_TLS_CRYPT_KEY_FILE,
)
from portal_format import utcnow


DatabaseConnection = Any
DatabaseRow = dict[str, Any]


def generate_openvpn_static_key_text() -> str:
    raw = os.urandom(256)
    hex_text = raw.hex()
    lines = [hex_text[i : i + 32] for i in range(0, len(hex_text), 32)]
    return "\n".join(
        [
            "#",
            "# 2048 bit OpenVPN static key",
            "#",
            "-----BEGIN OpenVPN Static key V1-----",
            *lines,
            "-----END OpenVPN Static key V1-----",
            "",
        ]
    )


def ensure_shared_openvpn_materials() -> dict[str, str]:
    required_files = {
        "ca_key": SHARED_OPENVPN_CA_KEY_FILE,
        "ca_cert": SHARED_OPENVPN_CA_CERT_FILE,
        "server_key": SHARED_OPENVPN_SERVER_KEY_FILE,
        "server_cert": SHARED_OPENVPN_SERVER_CERT_FILE,
        "tls_crypt_key": SHARED_OPENVPN_TLS_CRYPT_KEY_FILE,
    }
    if all(path.exists() and path.read_text(encoding="utf-8").strip() for path in required_files.values()):
        return {
            key: path.read_text(encoding="utf-8").strip()
            for key, path in required_files.items()
        }

    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "vpn-manager-ca"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "vpn-manager"),
        ]
    )
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "vpn-manager-server"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "vpn-manager"),
        ]
    )
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_subject)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    materials = {
        "ca_key": ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8"),
        "ca_cert": ca_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
        "server_key": server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8"),
        "server_cert": server_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
        "tls_crypt_key": generate_openvpn_static_key_text(),
    }
    for key, path in required_files.items():
        path.write_text(materials[key].strip() + "\n", encoding="utf-8")
    return materials


def build_openvpn_common_name(user: DatabaseRow) -> str:
    user_id = int(row_get(user, "id", 0) or 0)
    if user_id <= 0:
        raise RuntimeError("无法为用户生成 OpenVPN 身份。")
    return f"{OPENVPN_COMMON_NAME_PREFIX}{user_id}"


def parse_openvpn_user_id_from_common_name(common_name: str | None) -> int | None:
    value = (common_name or "").strip()
    if not value:
        return None
    match = re.fullmatch(rf"{re.escape(OPENVPN_COMMON_NAME_PREFIX)}(\d+)", value)
    if not match:
        return None
    try:
        user_id = int(match.group(1))
    except Exception:
        return None
    return user_id if user_id > 0 else None


def certificate_not_valid_before_utc(cert: x509.Certificate) -> datetime:
    value = getattr(cert, "not_valid_before_utc", None)
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc)
    value = cert.not_valid_before
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def certificate_not_valid_after_utc(cert: x509.Certificate) -> datetime:
    value = getattr(cert, "not_valid_after_utc", None)
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc)
    value = cert.not_valid_after
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def should_rotate_openvpn_client_identity(
    *,
    common_name: str,
    cert_text: str,
    key_text: str,
) -> bool:
    cert_raw = (cert_text or "").strip()
    key_raw = (key_text or "").strip()
    if not cert_raw or not key_raw:
        return True
    try:
        cert = x509.load_pem_x509_certificate(cert_raw.encode("utf-8"))
        private_key = serialization.load_pem_private_key(
            key_raw.encode("utf-8"),
            password=None,
        )
    except Exception:
        return True
    try:
        subject_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except Exception:
        return True
    if (subject_cn or "").strip() != common_name:
        return True
    now = utcnow()
    if certificate_not_valid_before_utc(cert) > now + timedelta(minutes=5):
        return True
    renew_before = now + timedelta(days=max(1, OPENVPN_CLIENT_CERT_RENEW_BEFORE_DAYS))
    if certificate_not_valid_after_utc(cert) <= renew_before:
        return True
    try:
        cert_public_bytes = cert.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key_public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except Exception:
        return True
    return cert_public_bytes != key_public_bytes


def issue_openvpn_client_identity(common_name: str) -> dict[str, str]:
    materials = ensure_shared_openvpn_materials()
    ca_key = serialization.load_pem_private_key(
        materials["ca_key"].encode("utf-8"),
        password=None,
    )
    ca_cert = x509.load_pem_x509_certificate(materials["ca_cert"].encode("utf-8"))
    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = utcnow()
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "vpn-manager-client"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=OPENVPN_CLIENT_CERT_VALID_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )
    return {
        "openvpn_common_name": common_name,
        "openvpn_client_cert": cert.public_bytes(serialization.Encoding.PEM)
        .decode("utf-8")
        .strip(),
        "openvpn_client_key": client_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        .decode("utf-8")
        .strip(),
    }


def ensure_user_openvpn_client_identity(
    db: DatabaseConnection,
    user: DatabaseRow,
) -> DatabaseRow:
    common_name = build_openvpn_common_name(user)
    cert_text = (row_get(user, "openvpn_client_cert", "") or "").strip()
    key_text = (row_get(user, "openvpn_client_key", "") or "").strip()
    stored_common_name = (row_get(user, "openvpn_common_name", "") or "").strip()
    needs_rotate = stored_common_name != common_name or should_rotate_openvpn_client_identity(
        common_name=common_name,
        cert_text=cert_text,
        key_text=key_text,
    )
    if needs_rotate:
        bundle = issue_openvpn_client_identity(common_name)
        db.execute(
            """
            UPDATE users
            SET openvpn_common_name = ?,
                openvpn_client_cert = ?,
                openvpn_client_key = ?
            WHERE id = ?
            """,
            (
                bundle["openvpn_common_name"],
                bundle["openvpn_client_cert"],
                bundle["openvpn_client_key"],
                int(user["id"]),
            ),
        )
        refreshed = db.execute("SELECT * FROM users WHERE id = ?", (int(user["id"]),)).fetchone()
        if not refreshed:
            raise RuntimeError("OpenVPN 证书更新后用户不存在。")
        return refreshed
    if not stored_common_name:
        db.execute(
            "UPDATE users SET openvpn_common_name = ? WHERE id = ?",
            (common_name, int(user["id"])),
        )
        refreshed = db.execute("SELECT * FROM users WHERE id = ?", (int(user["id"]),)).fetchone()
        if refreshed:
            return refreshed
    return user
