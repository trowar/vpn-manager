from functools import wraps
import os
import random
import re
import smtplib
import string
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

from flask import (
    Response,
    abort,
    Blueprint,
    flash,
    current_app,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from .db import get_db, init_db, utcnow_iso

bp = Blueprint("main", __name__)


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
CAPTCHA_RE = re.compile(r"^[a-zA-Z0-9_-]+$")


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def get_setting(key: str, default_value: str = "") -> str:
    db = get_db()
    row = db.execute("SELECT value FROM app_settings WHERE key = ? LIMIT 1", (key,)).fetchone()
    if not row:
        return default_value
    return row["value"]


def set_setting(key: str, value: str):
    db = get_db()
    db.execute(
        """
        INSERT INTO app_settings (key, value, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
        """,
        (key, value, utcnow_iso()),
    )
    db.commit()


def is_registration_open() -> bool:
    return get_setting("registration_open", "1") == "1"


def normalize_email(raw: str) -> str:
    return (raw or "").strip().lower()


def is_valid_email(email: str) -> bool:
    return EMAIL_RE.match(email) is not None


def session_login(user):
    session.clear()
    session["uid"] = int(user["id"])
    session["session_version"] = int(user["session_version"] or 1)


def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ? LIMIT 1", (uid,)).fetchone()
    if not user:
        session.clear()
        return None

    session_version = session.get("session_version")
    if session_version is None or int(session_version) != int(user["session_version"] or 1):
        session.clear()
        return None
    return user


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user:
            return redirect(url_for("main.login"))
        return fn(*args, **kwargs)

    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user or user["role"] != "admin":
            flash("需要管理员权限。", "error")
            return redirect(url_for("main.login"))
        if int(user["must_change_password"] or 0) == 1 and request.endpoint not in {
            "main.admin_change_password",
            "main.logout",
        }:
            return redirect(url_for("main.admin_change_password"))
        return fn(*args, **kwargs)

    return wrapper


def cleanup_expired_data():
    db = get_db()
    now_iso = utcnow_iso()
    db.execute(
        """
        UPDATE email_verifications
        SET status = 'expired'
        WHERE status = 'pending' AND expire_at < ?
        """,
        (now_iso,),
    )
    unverified_cutoff = (now_utc() - timedelta(hours=24)).replace(microsecond=0).isoformat()
    db.execute(
        """
        DELETE FROM users
        WHERE role = 'user' AND email_verified = 0 AND created_at < ?
        """,
        (unverified_cutoff,),
    )
    db.commit()


def captcha_session_key(scene: str) -> str:
    safe_scene = scene if CAPTCHA_RE.match(scene or "") else "default"
    return f"captcha_{safe_scene}"


def generate_captcha_text(length: int = 5) -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(random.choice(alphabet) for _ in range(length))


def validate_captcha(scene: str, user_input: str) -> bool:
    key = captcha_session_key(scene)
    payload = session.get(key)
    if not payload:
        return False
    expire_at = payload.get("expire_at")
    if not expire_at:
        return False
    try:
        if datetime.fromisoformat(expire_at) < now_utc():
            return False
    except ValueError:
        return False
    if (user_input or "").strip().upper() != (payload.get("text") or "").upper():
        return False
    session.pop(key, None)
    return True


def can_send_email_code(email: str, purpose: str):
    db = get_db()
    now = now_utc()
    minute_ago = (now - timedelta(seconds=60)).replace(microsecond=0).isoformat()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()

    recent = db.execute(
        """
        SELECT created_at FROM email_verifications
        WHERE email = ? AND purpose = ? AND created_at >= ?
        ORDER BY id DESC LIMIT 1
        """,
        (email, purpose, minute_ago),
    ).fetchone()
    if recent:
        try:
            delta = now - datetime.fromisoformat(recent["created_at"])
            wait_seconds = max(1, 60 - int(delta.total_seconds()))
        except ValueError:
            wait_seconds = 60
        return False, f"发送过于频繁，请在 {wait_seconds} 秒后重试。"

    today_count = db.execute(
        """
        SELECT COUNT(1) AS c FROM email_verifications
        WHERE email = ? AND created_at >= ?
        """,
        (email, today_start),
    ).fetchone()
    if int(today_count["c"] or 0) >= 10:
        return False, "该邮箱今日验证码发送次数已达上限（10 次）。"

    return True, ""


def create_email_code(email: str, purpose: str, code: str):
    db = get_db()
    created_at = utcnow_iso()
    expire_at = (now_utc() + timedelta(minutes=10)).replace(microsecond=0).isoformat()
    db.execute(
        """
        INSERT INTO email_verifications (email, purpose, code, status, ip_address, expire_at, created_at)
        VALUES (?, ?, ?, 'pending', ?, ?, ?)
        """,
        (email, purpose, code, request.remote_addr or "", expire_at, created_at),
    )
    db.commit()


def consume_email_code(email: str, purpose: str, code: str):
    db = get_db()
    now_iso = utcnow_iso()
    row = db.execute(
        """
        SELECT id FROM email_verifications
        WHERE email = ? AND purpose = ? AND code = ? AND status = 'pending' AND expire_at >= ?
        ORDER BY id DESC LIMIT 1
        """,
        (email, purpose, (code or "").strip(), now_iso),
    ).fetchone()
    if not row:
        return False
    db.execute(
        """
        UPDATE email_verifications
        SET status = 'used', used_at = ?
        WHERE id = ?
        """,
        (now_iso, int(row["id"])),
    )
    db.commit()
    return True


def send_email_code(email: str, purpose: str, code: str):
    smtp_host = os.environ.get("SMTP_HOST", "").strip()
    smtp_user = os.environ.get("SMTP_USER", "").strip()
    smtp_pass = os.environ.get("SMTP_PASS", "").strip()
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_from = os.environ.get("SMTP_FROM", smtp_user).strip()
    use_tls = os.environ.get("SMTP_USE_TLS", "1") != "0"

    subject = "VPN 平台邮箱验证码"
    body = (
        f"您好，\n\n"
        f"您正在进行 {purpose} 操作，验证码为：{code}\n"
        f"验证码有效期 10 分钟，请勿泄露给他人。\n\n"
        f"若非本人操作，请忽略本邮件。"
    )

    if not smtp_host or not smtp_from:
        current_app.logger.warning("SMTP 未配置，邮箱 %s 的 %s 验证码：%s", email, purpose, code)
        return True, f"测试环境验证码：{code}（未配置 SMTP，已写入日志）"

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = smtp_from
    msg["To"] = email
    msg.set_content(body)

    try:
        if use_tls:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
                server.starttls()
                if smtp_user and smtp_pass:
                    server.login(smtp_user, smtp_pass)
                server.send_message(msg)
        else:
            with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=15) as server:
                if smtp_user and smtp_pass:
                    server.login(smtp_user, smtp_pass)
                server.send_message(msg)
    except Exception as exc:  # noqa: BLE001
        current_app.logger.exception("发送验证码邮件失败: %s", exc)
        return False, "验证码发送失败，请稍后重试。"

    return True, "验证码已发送，请检查邮箱。"


@bp.before_app_request
def ensure_bootstrap():
    init_db()
    cleanup_expired_data()


@bp.route("/")
def index():
    return render_template(
        "index.html",
        user=current_user(),
        registration_open=is_registration_open(),
    )


@bp.route("/captcha.svg")
def captcha_svg():
    scene = request.args.get("scene", "default")
    if not CAPTCHA_RE.match(scene):
        scene = "default"

    text = generate_captcha_text()
    expire_at = (now_utc() + timedelta(minutes=5)).replace(microsecond=0).isoformat()
    session[captcha_session_key(scene)] = {
        "text": text,
        "expire_at": expire_at,
    }

    chars = []
    for idx, char in enumerate(text):
        x = 18 + idx * 22
        y = 34 + random.randint(-3, 3)
        rotate = random.randint(-18, 18)
        chars.append(
            f'<text x="{x}" y="{y}" transform="rotate({rotate} {x} {y})">{char}</text>'
        )

    lines = []
    for _ in range(4):
        x1, y1 = random.randint(0, 130), random.randint(0, 44)
        x2, y2 = random.randint(0, 130), random.randint(0, 44)
        lines.append(
            (
                '<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" '
                'stroke="#9fb4d4" stroke-width="1" />'
            ).format(x1=x1, y1=y1, x2=x2, y2=y2)
        )

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="130" height="44" viewBox="0 0 130 44">
<rect width="130" height="44" fill="#eef3fb" rx="6" ry="6" />
{''.join(lines)}
<g fill="#113366" font-family="Verdana, sans-serif" font-size="24" font-weight="700">
{''.join(chars)}
</g>
</svg>"""
    return Response(svg, mimetype="image/svg+xml", headers={"Cache-Control": "no-store"})


@bp.route("/register/send-code", methods=["POST"])
def register_send_code():
    if not is_registration_open():
        abort(404)

    email = normalize_email(request.form.get("email"))
    captcha = request.form.get("captcha")
    if not is_valid_email(email):
        flash("邮箱格式不正确。", "error")
        return redirect(url_for("main.register"))

    if not validate_captcha("register", captcha):
        flash("图片验证码错误或已过期。", "error")
        return redirect(url_for("main.register"))

    db = get_db()
    existing = db.execute("SELECT id FROM users WHERE email = ? LIMIT 1", (email,)).fetchone()
    if existing:
        flash("该邮箱已注册，请直接登录。", "error")
        return redirect(url_for("main.register"))

    ok, msg = can_send_email_code(email, "register")
    if not ok:
        flash(msg, "error")
        return redirect(url_for("main.register"))

    code = "".join(random.choice(string.digits) for _ in range(6))
    create_email_code(email, "register", code)
    sent_ok, sent_msg = send_email_code(email, "注册", code)
    flash(sent_msg, "success" if sent_ok else "error")
    return redirect(url_for("main.register"))


@bp.route("/register", methods=["GET", "POST"])
def register():
    if not is_registration_open():
        abort(404)

    if request.method == "POST":
        email = normalize_email(request.form.get("email"))
        password = request.form.get("password") or ""
        confirm_password = request.form.get("confirm_password") or ""
        email_code = (request.form.get("email_code") or "").strip()
        captcha = request.form.get("captcha")

        if not validate_captcha("register", captcha):
            flash("图片验证码错误或已过期。", "error")
            return render_template("register.html", user=current_user(), registration_open=True)

        if not is_valid_email(email):
            flash("邮箱格式不正确。", "error")
            return render_template("register.html", user=current_user(), registration_open=True)
        if len(password) < 8:
            flash("密码至少 8 位。", "error")
            return render_template("register.html", user=current_user(), registration_open=True)
        if password != confirm_password:
            flash("两次密码输入不一致。", "error")
            return render_template("register.html", user=current_user(), registration_open=True)

        db = get_db()
        exists = db.execute("SELECT id FROM users WHERE email = ? LIMIT 1", (email,)).fetchone()
        if exists:
            flash("该邮箱已注册，请直接登录。", "error")
            return render_template("register.html", user=current_user(), registration_open=True)

        if not consume_email_code(email, "register", email_code):
            flash("邮箱验证码无效或已过期。", "error")
            return render_template("register.html", user=current_user(), registration_open=True)

        now_iso = utcnow_iso()
        db.execute(
            """
            INSERT INTO users (
                email, password_hash, role, email_verified, must_change_password,
                session_version, status, created_at, updated_at
            ) VALUES (?, ?, 'user', 1, 0, 1, 'active', ?, ?)
            """,
            (email, generate_password_hash(password), now_iso, now_iso),
        )
        db.commit()
        flash("注册成功，请登录。", "success")
        return redirect(url_for("main.login"))

    return render_template("register.html", user=current_user(), registration_open=True)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = normalize_email(request.form.get("email"))
        password = request.form.get("password") or ""
        captcha = request.form.get("captcha")

        if not validate_captcha("login", captcha):
            flash("图片验证码错误或已过期。", "error")
            return render_template("login.html", user=current_user(), registration_open=is_registration_open())

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email = ? LIMIT 1", (email,)).fetchone()
        if not user or not check_password_hash(user["password_hash"], password):
            flash("账号或密码错误。", "error")
            return render_template("login.html", user=current_user(), registration_open=is_registration_open())
        if user["role"] != "admin" and int(user["email_verified"] or 0) != 1:
            flash("邮箱尚未验证，暂时无法登录。", "error")
            return render_template("login.html", user=current_user(), registration_open=is_registration_open())
        if user["status"] != "active":
            flash("账号已被停用，请联系管理员。", "error")
            return render_template("login.html", user=current_user(), registration_open=is_registration_open())

        session_login(user)
        if user["role"] == "admin":
            return redirect(url_for("main.admin_dashboard"))
        return redirect(url_for("main.user_dashboard"))
    return render_template("login.html", user=current_user(), registration_open=is_registration_open())


@bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("main.login"))


@bp.route("/password-recover/send-code", methods=["POST"])
def password_recover_send_code():
    email = normalize_email(request.form.get("email"))
    captcha = request.form.get("captcha")
    if not is_valid_email(email):
        flash("邮箱格式不正确。", "error")
        return redirect(url_for("main.password_recover"))

    if not validate_captcha("recover", captcha):
        flash("图片验证码错误或已过期。", "error")
        return redirect(url_for("main.password_recover"))

    db = get_db()
    user = db.execute("SELECT id FROM users WHERE email = ? LIMIT 1", (email,)).fetchone()
    if not user:
        flash("该邮箱尚未注册。", "error")
        return redirect(url_for("main.password_recover"))

    ok, msg = can_send_email_code(email, "recover")
    if not ok:
        flash(msg, "error")
        return redirect(url_for("main.password_recover"))

    code = "".join(random.choice(string.digits) for _ in range(6))
    create_email_code(email, "recover", code)
    sent_ok, sent_msg = send_email_code(email, "找回密码", code)
    flash(sent_msg, "success" if sent_ok else "error")
    return redirect(url_for("main.password_recover"))


@bp.route("/password-recover", methods=["GET", "POST"])
def password_recover():
    if request.method == "POST":
        email = normalize_email(request.form.get("email"))
        code = (request.form.get("email_code") or "").strip()
        new_password = request.form.get("new_password") or ""
        confirm_password = request.form.get("confirm_password") or ""
        captcha = request.form.get("captcha")

        if not validate_captcha("recover", captcha):
            flash("图片验证码错误或已过期。", "error")
            return render_template("password_recover.html", user=current_user())
        if not is_valid_email(email):
            flash("邮箱格式不正确。", "error")
            return render_template("password_recover.html", user=current_user())
        if len(new_password) < 8:
            flash("新密码至少 8 位。", "error")
            return render_template("password_recover.html", user=current_user())
        if new_password != confirm_password:
            flash("两次密码输入不一致。", "error")
            return render_template("password_recover.html", user=current_user())
        if not consume_email_code(email, "recover", code):
            flash("邮箱验证码无效或已过期。", "error")
            return render_template("password_recover.html", user=current_user())

        db = get_db()
        user = db.execute("SELECT id FROM users WHERE email = ? LIMIT 1", (email,)).fetchone()
        if not user:
            flash("该邮箱尚未注册。", "error")
            return render_template("password_recover.html", user=current_user())

        db.execute(
            """
            UPDATE users
            SET password_hash = ?, session_version = session_version + 1, updated_at = ?
            WHERE id = ?
            """,
            (generate_password_hash(new_password), utcnow_iso(), int(user["id"])),
        )
        db.commit()
        session.clear()
        flash("密码已重置，请使用新密码登录。", "success")
        return redirect(url_for("main.login"))

    return render_template("password_recover.html", user=current_user())


@bp.route("/admin")
@login_required
@admin_required
def admin_dashboard():
    db = get_db()
    pending_codes = db.execute(
        "SELECT COUNT(1) AS c FROM email_verifications WHERE status = 'pending'"
    ).fetchone()
    user_count = db.execute("SELECT COUNT(1) AS c FROM users WHERE role = 'user'").fetchone()
    return render_template(
        "admin_dashboard.html",
        user=current_user(),
        registration_open=is_registration_open(),
        pending_codes=int(pending_codes["c"] or 0),
        user_count=int(user_count["c"] or 0),
    )


@bp.route("/admin/settings/registration", methods=["POST"])
@login_required
@admin_required
def admin_set_registration():
    registration_open = request.form.get("registration_open") == "1"
    set_setting("registration_open", "1" if registration_open else "0")
    flash("开放注册设置已更新。", "success")
    return redirect(url_for("main.admin_dashboard"))


@bp.route("/admin/change-password", methods=["GET", "POST"])
@login_required
def admin_change_password():
    user = current_user()
    if not user or user["role"] != "admin":
        return redirect(url_for("main.login"))

    if request.method == "POST":
        new_password = request.form.get("new_password") or ""
        confirm_password = request.form.get("confirm_password") or ""
        if len(new_password) < 8:
            flash("新密码至少 8 位。", "error")
            return render_template("admin_change_password.html", user=user)
        if new_password != confirm_password:
            flash("两次密码输入不一致。", "error")
            return render_template("admin_change_password.html", user=user)

        db = get_db()
        db.execute(
            """
            UPDATE users
            SET password_hash = ?, must_change_password = 0, session_version = session_version + 1, updated_at = ?
            WHERE id = ?
            """,
            (generate_password_hash(new_password), utcnow_iso(), int(user["id"])),
        )
        db.commit()
        refreshed = db.execute("SELECT * FROM users WHERE id = ? LIMIT 1", (int(user["id"]),)).fetchone()
        session_login(refreshed)
        flash("管理员密码已更新。", "success")
        return redirect(url_for("main.admin_dashboard"))

    return render_template("admin_change_password.html", user=user)


@bp.route("/dashboard")
@login_required
def user_dashboard():
    return render_template("user_dashboard.html", user=current_user())
