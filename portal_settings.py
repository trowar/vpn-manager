from portal_config import (
    MAIL_SECURITY_CHOICES,
    MAIL_SECURITY_LABELS,
    MAIL_SECURITY_STARTTLS,
    SETTING_GIFT_DURATION_MONTHS,
    SETTING_GIFT_TRAFFIC_GB,
    SETTING_OPENVPN_OPEN,
    SETTING_ORDER_EXPIRE_HOURS,
    SETTING_REGISTRATION_OPEN,
    SETTING_SITE_TITLE,
    SETTING_SYSTEM_UPGRADE_FINISHED_AT,
    SETTING_SYSTEM_UPGRADE_STARTED_AT,
    SETTING_SYSTEM_UPGRADE_STATUS,
    SETTING_SYSTEM_UPGRADE_SUMMARY,
    SETTING_TELEGRAM_CONTACT,
    )
from portal_format import utcnow_iso


def upsert_app_setting(db, key: str, value: str) -> None:
    db.execute(
        """
        INSERT INTO app_settings (setting_key, setting_value, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(setting_key) DO UPDATE SET
            setting_value = excluded.setting_value,
            updated_at = excluded.updated_at
        """,
        (key, value, utcnow_iso()),
    )


def get_app_setting(db, key: str, default: str = "") -> str:
    row = db.execute(
        """
        SELECT setting_value
        FROM app_settings
        WHERE setting_key = ?
        LIMIT 1
        """,
        (key,),
    ).fetchone()
    if not row:
        return default
    return (row["setting_value"] or "").strip() or default


def load_named_settings(db, keys: tuple[str, ...]) -> dict[str, str]:
    if not keys:
        return {}
    rows = db.execute(
        """
        SELECT setting_key, setting_value
        FROM app_settings
        WHERE setting_key IN ({})
        """.format(",".join("?" for _ in keys)),
        keys,
    ).fetchall()
    values = {key: "" for key in keys}
    for row in rows:
        values[row["setting_key"]] = (row["setting_value"] or "").strip()
    return values


def parse_bool_setting(raw: str | None, default: bool = False) -> bool:
    value = (raw or "").strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    return default


def parse_int_setting(raw: str | None, default: int, *, min_value: int = 0) -> int:
    try:
        value = int((raw or "").strip())
    except Exception:
        value = default
    if value < min_value:
        return min_value
    return value


def ensure_default_system_settings(db) -> None:
    defaults = {
        SETTING_REGISTRATION_OPEN: "0",
        SETTING_ORDER_EXPIRE_HOURS: "24",
        SETTING_GIFT_DURATION_MONTHS: "0",
        SETTING_GIFT_TRAFFIC_GB: "0",
        SETTING_TELEGRAM_CONTACT: "",
        SETTING_SITE_TITLE: "新世界发展科技有限公司边缘节点网络管理系统",        SETTING_OPENVPN_OPEN: "0",
        SETTING_SYSTEM_UPGRADE_STATUS: "idle",
        SETTING_SYSTEM_UPGRADE_SUMMARY: "",
        SETTING_SYSTEM_UPGRADE_STARTED_AT: "",
        SETTING_SYSTEM_UPGRADE_FINISHED_AT: "",
    }
    for key, value in defaults.items():
        current = get_app_setting(db, key, "")
        if current == "":
            upsert_app_setting(db, key, value)


def normalize_mail_security(raw: str | None) -> str:
    value = (raw or "").strip().lower()
    if value in MAIL_SECURITY_CHOICES:
        return value
    return MAIL_SECURITY_STARTTLS


def format_mail_security_label(raw: str | None) -> str:
    return MAIL_SECURITY_LABELS.get(
        normalize_mail_security(raw),
        MAIL_SECURITY_LABELS[MAIL_SECURITY_STARTTLS],
    )


def format_sender_display(from_name: str | None, from_email: str | None) -> str:
    sender_name = (from_name or "").strip()
    sender_email = (from_email or "").strip()
    if sender_name and sender_email:
        return f"{sender_name} <{sender_email}>"
    return sender_email or "-"
