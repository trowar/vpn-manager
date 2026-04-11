from functools import wraps

from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from .db import get_db, init_db, utcnow_iso

bp = Blueprint("main", __name__)


def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    db = get_db()
    return db.execute("SELECT * FROM users WHERE id = ? LIMIT 1", (uid,)).fetchone()


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


@bp.before_app_request
def ensure_bootstrap():
    init_db()


@bp.route("/")
def index():
    return render_template("index.html", user=current_user())


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip()
        password = request.form.get("password") or ""
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email = ? LIMIT 1", (email,)).fetchone()
        if not user or not check_password_hash(user["password_hash"], password):
            flash("账号或密码错误。", "error")
            return render_template("login.html", user=current_user())
        session.clear()
        session["uid"] = int(user["id"])
        if user["role"] == "admin":
            return redirect(url_for("main.admin_dashboard"))
        return redirect(url_for("main.user_dashboard"))
    return render_template("login.html", user=current_user())


@bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("main.login"))


@bp.route("/admin")
@login_required
@admin_required
def admin_dashboard():
    return render_template("admin_dashboard.html", user=current_user())


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
            SET password_hash = ?, must_change_password = 0, updated_at = ?
            WHERE id = ?
            """,
            (generate_password_hash(new_password), utcnow_iso(), int(user["id"])),
        )
        db.commit()
        flash("管理员密码已更新。", "success")
        return redirect(url_for("main.admin_dashboard"))

    return render_template("admin_change_password.html", user=user)


@bp.route("/dashboard")
@login_required
def user_dashboard():
    return render_template("user_dashboard.html", user=current_user())

