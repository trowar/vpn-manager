from __future__ import annotations

from datetime import timedelta
import random

from flask import session


def captcha_session_key(scene: str, *, scenes: tuple[str, ...], default_scene: str) -> str:
    safe_scene = (scene or "").strip().lower()
    if safe_scene not in scenes:
        safe_scene = default_scene
    return f"captcha_{safe_scene}"


def generate_captcha_text(length: int = 5) -> str:
    chars = "23456789"
    return "".join(random.choice(chars) for _ in range(length))


def validate_captcha_input(
    scene: str,
    value: str,
    *,
    scenes: tuple[str, ...],
    default_scene: str,
    utcnow,
    parse_iso,
) -> bool:
    key = captcha_session_key(scene, scenes=scenes, default_scene=default_scene)
    payload = session.get(key)
    if not payload:
        return False
    input_value = (value or "").strip().upper()
    if not input_value:
        return False
    records = payload if isinstance(payload, list) else [payload]
    now = utcnow()
    kept_records = []
    matched = False
    for record in records:
        if not isinstance(record, dict):
            continue
        expire_at_raw = record.get("expire_at")
        if not expire_at_raw:
            continue
        try:
            expire_at = parse_iso(expire_at_raw)
        except Exception:
            continue
        if not expire_at or expire_at < now:
            continue
        expected = str(record.get("text") or "").strip().upper()
        if input_value == expected:
            matched = True
            continue
        kept_records.append(record)
    session[key] = kept_records[-3:]
    return matched


def create_captcha_svg_response_payload(
    scene: str,
    *,
    scenes: tuple[str, ...],
    default_scene: str,
    ttl_minutes: int,
    utcnow,
) -> str:
    safe_scene = (scene or default_scene).strip().lower()
    if safe_scene not in scenes:
        safe_scene = default_scene

    text = generate_captcha_text()
    key = captcha_session_key(safe_scene, scenes=scenes, default_scene=default_scene)
    existing = session.get(key)
    records = existing if isinstance(existing, list) else ([existing] if existing else [])
    records = [record for record in records if isinstance(record, dict)]
    records.append(
        {
            "text": text,
            "expire_at": (utcnow() + timedelta(minutes=ttl_minutes)).isoformat(),
        }
    )
    session[key] = records[-3:]

    chars: list[str] = []
    for idx, char in enumerate(text):
        x = 14 + idx * 22
        y = 32 + random.randint(-3, 3)
        rotate = random.randint(-16, 16)
        chars.append(
            f'<text x="{x}" y="{y}" transform="rotate({rotate} {x} {y})">{char}</text>'
        )
    lines: list[str] = []
    for _ in range(4):
        x1, y1 = random.randint(0, 124), random.randint(0, 40)
        x2, y2 = random.randint(0, 124), random.randint(0, 40)
        lines.append(
            f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="#a7b8d8" stroke-width="1" />'
        )
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" width="124" height="40" viewBox="0 0 124 40">'
        '<rect width="124" height="40" rx="6" ry="6" fill="#edf2fb" />'
        + "".join(lines)
        + '<g font-family="Verdana,sans-serif" font-size="23" font-weight="700" fill="#0f2748">'
        + "".join(chars)
        + "</g></svg>"
    )
