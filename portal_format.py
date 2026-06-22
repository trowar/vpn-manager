import calendar
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import Any

from portal_auth import row_get
from portal_config import (
    ADMIN_UI_TZ,
    PLAN_DURATION_UNIT_DAY,
    PLAN_DURATION_UNIT_MONTH,
    PLAN_DURATION_UNIT_YEAR,
    PLAN_DURATION_UNITS,
    PLAN_MODE_DURATION,
    PLAN_MODE_TRAFFIC,
    PLAN_MODES,
    USDT_DEFAULT_NETWORK,
    USDT_RECEIVE_ADDRESS,
)


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def utcnow_iso() -> str:
    return utcnow().isoformat()


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def add_months(dt: datetime, months: int) -> datetime:
    total_month = dt.month - 1 + months
    year = dt.year + total_month // 12
    month = total_month % 12 + 1
    day = min(dt.day, calendar.monthrange(year, month)[1])
    return dt.replace(year=year, month=month, day=day)


def format_utc(value: str | None) -> str:
    dt = parse_iso(value)
    if not dt:
        return "-"
    return dt.astimezone(ADMIN_UI_TZ).strftime("%Y-%m-%d %H:%M:%S")


def format_admin_local_date_input(value: str | None) -> str:
    dt = parse_iso(value)
    if not dt:
        return ""
    return dt.astimezone(ADMIN_UI_TZ).strftime("%Y-%m-%d")


def format_admin_local_input(value: str | None) -> str:
    return format_admin_local_date_input(value)


def parse_admin_local_date(raw: str) -> datetime:
    value = (raw or "").strip()
    local_dt = datetime.strptime(value, "%Y-%m-%d").replace(
        hour=0,
        minute=0,
        second=0,
        microsecond=0,
        tzinfo=ADMIN_UI_TZ,
    )
    return local_dt.astimezone(timezone.utc)


def parse_admin_local_datetime(raw: str) -> datetime:
    return parse_admin_local_date(raw)


def parse_usdt_amount(raw: str, fallback: str) -> Decimal:
    value = (raw or "").strip() or fallback
    try:
        amount = Decimal(value)
        if amount <= 0:
            raise InvalidOperation("amount must be positive")
        return amount.quantize(Decimal("0.01"))
    except (InvalidOperation, ValueError):
        return Decimal(fallback).quantize(Decimal("0.01"))


def parse_usdt_amount_strict(raw: str) -> Decimal:
    amount = Decimal((raw or "").strip())
    if amount <= 0:
        raise InvalidOperation("amount must be positive")
    return amount.quantize(Decimal("0.01"))


def format_usdt(value: str | Decimal | None) -> str:
    if value is None:
        return "-"
    if isinstance(value, str):
        try:
            amount = Decimal(value)
        except (InvalidOperation, ValueError):
            return value
    else:
        amount = value
    amount = amount.quantize(Decimal("0.01"))
    return f"{amount:.2f}"


def default_payment_settings() -> dict[str, str]:
    return {
        "usdt_receive_address": USDT_RECEIVE_ADDRESS,
        "usdt_default_network": USDT_DEFAULT_NETWORK,
    }


def normalize_plan_mode(mode: str | None) -> str:
    raw_mode = (mode or "").strip().lower()
    if raw_mode in PLAN_MODES:
        return raw_mode
    if raw_mode in {"time", "month", "months"}:
        return PLAN_MODE_DURATION
    if raw_mode in {"traffic_gb", "gb", "flow", "data"}:
        return PLAN_MODE_TRAFFIC
    return PLAN_MODE_DURATION


def plan_mode_label(mode: str | None) -> str:
    normalized = normalize_plan_mode(mode)
    if normalized == PLAN_MODE_TRAFFIC:
        return "按流量收费"
    return "按时长收费"


def normalize_duration_unit(unit: str | None) -> str:
    raw_unit = (unit or "").strip().lower()
    if raw_unit in PLAN_DURATION_UNITS:
        return raw_unit
    alias_map = {
        "d": PLAN_DURATION_UNIT_DAY,
        "day": PLAN_DURATION_UNIT_DAY,
        "days": PLAN_DURATION_UNIT_DAY,
        "天": PLAN_DURATION_UNIT_DAY,
        "m": PLAN_DURATION_UNIT_MONTH,
        "month": PLAN_DURATION_UNIT_MONTH,
        "months": PLAN_DURATION_UNIT_MONTH,
        "月": PLAN_DURATION_UNIT_MONTH,
        "个月": PLAN_DURATION_UNIT_MONTH,
        "y": PLAN_DURATION_UNIT_YEAR,
        "year": PLAN_DURATION_UNIT_YEAR,
        "years": PLAN_DURATION_UNIT_YEAR,
        "年": PLAN_DURATION_UNIT_YEAR,
    }
    return alias_map.get(raw_unit, PLAN_DURATION_UNIT_MONTH)


def plan_duration_unit_label(unit: str | None) -> str:
    normalized = normalize_duration_unit(unit)
    if normalized == PLAN_DURATION_UNIT_DAY:
        return "天"
    if normalized == PLAN_DURATION_UNIT_YEAR:
        return "年"
    return "个月"


def duration_value_to_legacy_months(value: int, unit: str | None) -> int:
    normalized_unit = normalize_duration_unit(unit)
    normalized_value = max(0, int(value or 0))
    if normalized_unit == PLAN_DURATION_UNIT_YEAR:
        return normalized_value * 12
    if normalized_unit == PLAN_DURATION_UNIT_MONTH:
        return normalized_value
    return 0


def parse_positive_int(raw: str | None) -> int:
    value = int((raw or "").strip())
    if value <= 0:
        raise ValueError("must be positive")
    return value


def to_non_negative_int(raw) -> int:
    try:
        value = int(raw or 0)
    except Exception:
        value = 0
    return value if value >= 0 else 0


def resolve_duration_value_and_unit(
    *,
    duration_months: int,
    duration_value_raw,
    duration_unit_raw,
) -> tuple[int, str]:
    duration_value = to_non_negative_int(duration_value_raw)
    duration_unit = normalize_duration_unit(duration_unit_raw)
    if duration_value <= 0 and duration_months > 0:
        duration_value = duration_months
        duration_unit = PLAN_DURATION_UNIT_MONTH
    return duration_value, duration_unit


def format_plan_value(
    mode: str | None,
    duration_months: int,
    traffic_gb: int,
    *,
    duration_value: int | None = None,
    duration_unit: str | None = None,
) -> str:
    normalized = normalize_plan_mode(mode)
    if normalized == PLAN_MODE_TRAFFIC:
        if traffic_gb <= 0:
            return "流量未设置"
        return f"{traffic_gb} GB"
    resolved_value, resolved_unit = resolve_duration_value_and_unit(
        duration_months=duration_months,
        duration_value_raw=duration_value,
        duration_unit_raw=duration_unit,
    )
    if resolved_value <= 0:
        return "时长未设置"
    return f"{resolved_value} {plan_duration_unit_label(resolved_unit)}"


def format_plan_display_name(
    plan_name: str | None,
    mode: str | None,
    duration_months: int,
    traffic_gb: int,
    *,
    duration_value: int | None = None,
    duration_unit: str | None = None,
) -> str:
    name = (plan_name or "").strip()
    mode_prefix = "时长" if normalize_plan_mode(mode) == PLAN_MODE_DURATION else "流量"
    value_text = format_plan_value(
        mode,
        duration_months,
        traffic_gb,
        duration_value=duration_value,
        duration_unit=duration_unit,
    )
    if name:
        return f"{name}（{mode_prefix} {value_text}）"
    return f"{mode_prefix} {value_text}"


def format_order_plan(order: Any) -> str:
    plan_name = (row_get(order, "plan_name", "") or "").strip()
    plan_mode_raw = row_get(order, "plan_mode", "")
    plan_mode = normalize_plan_mode(plan_mode_raw) if plan_mode_raw else ""
    duration_months = to_non_negative_int(row_get(order, "plan_duration_months", 0))
    duration_value, duration_unit = resolve_duration_value_and_unit(
        duration_months=duration_months,
        duration_value_raw=row_get(order, "plan_duration_value", 0),
        duration_unit_raw=row_get(order, "plan_duration_unit", PLAN_DURATION_UNIT_MONTH),
    )
    traffic_gb = to_non_negative_int(row_get(order, "plan_traffic_gb", 0))
    if not duration_months:
        duration_months = to_non_negative_int(row_get(order, "plan_months", 0))
    if duration_value <= 0:
        duration_value, duration_unit = resolve_duration_value_and_unit(
            duration_months=duration_months,
            duration_value_raw=duration_value,
            duration_unit_raw=duration_unit,
        )
    if not plan_mode:
        plan_mode = PLAN_MODE_TRAFFIC if traffic_gb > 0 else PLAN_MODE_DURATION
    return format_plan_display_name(
        plan_name,
        plan_mode,
        duration_months,
        traffic_gb,
        duration_value=duration_value,
        duration_unit=duration_unit,
    )


def resolve_order_plan_snapshot(order: Any) -> dict:
    plan_name = (row_get(order, "plan_name", "") or "").strip()
    plan_mode_raw = row_get(order, "plan_mode", "")
    plan_mode = normalize_plan_mode(plan_mode_raw) if plan_mode_raw else ""
    duration_months = to_non_negative_int(row_get(order, "plan_duration_months", 0))
    duration_value, duration_unit = resolve_duration_value_and_unit(
        duration_months=duration_months,
        duration_value_raw=row_get(order, "plan_duration_value", 0),
        duration_unit_raw=row_get(order, "plan_duration_unit", PLAN_DURATION_UNIT_MONTH),
    )
    traffic_gb = to_non_negative_int(row_get(order, "plan_traffic_gb", 0))
    if not duration_months:
        duration_months = to_non_negative_int(row_get(order, "plan_months", 0))
    if duration_value <= 0:
        duration_value, duration_unit = resolve_duration_value_and_unit(
            duration_months=duration_months,
            duration_value_raw=duration_value,
            duration_unit_raw=duration_unit,
        )
    if not plan_mode:
        plan_mode = PLAN_MODE_TRAFFIC if traffic_gb > 0 else PLAN_MODE_DURATION
    if not plan_name:
        plan_name = "流量套餐" if plan_mode == PLAN_MODE_TRAFFIC else "时长套餐"

    return {
        "plan_name": plan_name,
        "plan_mode": plan_mode,
        "duration_months": duration_months,
        "duration_value": duration_value,
        "duration_unit": duration_unit,
        "traffic_gb": traffic_gb,
        "display_name": format_plan_display_name(
            plan_name,
            plan_mode,
            duration_months,
            traffic_gb,
            duration_value=duration_value,
            duration_unit=duration_unit,
        ),
    }


def generate_plan_name(
    *,
    mode: str,
    duration_value: int | None = None,
    duration_unit: str | None = None,
    traffic_gb: int | None = None,
) -> str:
    normalized_mode = normalize_plan_mode(mode)
    if normalized_mode == PLAN_MODE_TRAFFIC:
        value = max(1, int(traffic_gb or 1))
        return f"{value}GB 流量包"
    value = max(1, int(duration_value or 1))
    unit_text = plan_duration_unit_label(duration_unit)
    return f"{value}{unit_text} 时长套餐"
