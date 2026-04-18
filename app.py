from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_mail import Mail
from dotenv import load_dotenv
from datetime import timedelta
import os

load_dotenv()

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"]        = os.getenv("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"]                 = os.getenv("JWT_SECRET_KEY")
app.config["JWT_TOKEN_LOCATION"]             = ["cookies"]
app.config["JWT_COOKIE_SECURE"]              = False
app.config["JWT_COOKIE_CSRF_PROTECT"]        = False
app.config["JWT_ACCESS_TOKEN_EXPIRES"]       = timedelta(hours=8)
app.config["MAIL_SERVER"]                    = "smtp.gmail.com"
app.config["MAIL_PORT"]                      = 587
app.config["MAIL_USE_TLS"]                   = True
app.config["MAIL_USERNAME"]                  = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"]                  = os.getenv("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"]            = os.getenv("MAIL_FROM")

db   = SQLAlchemy(app)
jwt  = JWTManager(app)
mail = Mail(app)

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    from flask import redirect, url_for
    return redirect(url_for("login"))

@jwt.unauthorized_loader
def unauthorized_callback(error):
    from flask import redirect, url_for
    return redirect(url_for("login"))

from models import init_models, create_tables
(User, Report, ReportRLS, Group, ReportGroup,
 Permission, RolePermission, AccessLog,
 PasswordResetCode, PortalSettings) = init_models(db)

def get_portal_settings():
    """Retorna dict com todas as configurações do portal."""
    rows = PortalSettings.query.all()
    return {r.key: r.value for r in rows}

@app.context_processor
def inject_settings():
    """Injeta as configurações em todos os templates."""
    try:
        settings = get_portal_settings()
        return {"portal": settings}
    except Exception:
        return {"portal": {
            "company_name": "Portal BI",
            "company_logo": "",
            "accent_color": "#00A8CC",
            "portal_name":  "Portal BI"
        }}

from routes import init_routes
init_routes(app, db, mail,
            User, Report, ReportRLS, Group, ReportGroup,
            Permission, RolePermission, AccessLog,
            PasswordResetCode, PortalSettings)

if __name__ == "__main__":
    with app.app_context():
        create_tables(db)
    app.run(debug=True, host="0.0.0.0", port=5000)