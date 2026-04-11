import os

from flask import Flask

from . import db, views


def create_app() -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("APP_SECRET_KEY", "dev-v1-secret"),
        DATABASE=os.path.join(app.instance_path, "vpn_platform_v1.db"),
    )

    os.makedirs(app.instance_path, exist_ok=True)

    db.init_app(app)
    app.register_blueprint(views.bp)

    @app.route("/healthz")
    def healthz():
        return {"ok": True, "service": "vpn-platform-v1"}, 200

    return app

