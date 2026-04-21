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
 PasswordResetCode, PortalSettings,
 RoleModulePermission, UserModulePermission, Role) = init_models(db)

@app.template_filter('user_count')
def user_count_filter(role_key):
    try:
        return User.query.filter_by(role=role_key).count()
    except Exception:
        return 0

@app.template_filter('role_info')
def role_info_filter(role_key):
    try:
        r = Role.query.filter_by(key=role_key).first()
        if r:
            return {"label": r.label, "color": r.color}
        return {"label": role_key, "color": "#7A8899"}
    except Exception:
        return {"label": role_key, "color": "#7A8899"}

def get_portal_settings():
    """Retorna dict com todas as configurações do portal."""
    rows = PortalSettings.query.all()
    return {r.key: r.value for r in rows}

@app.context_processor
def inject_settings():
    try:
        settings = get_portal_settings()
        from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
        try:
            verify_jwt_in_request(optional=True)
            uid = get_jwt_identity()
            if uid:
                u = User.query.get(int(uid))
                if u:
                    role_mods = {rm.module for rm in RoleModulePermission.query.filter_by(role=u.role).all()}
                    user_mods = {um.module for um in UserModulePermission.query.filter_by(user_id=u.id).all()}
                    available = role_mods | user_mods
                    if u.is_admin:
                        available = {m["key"] for m in SYSTEM_MODULES}
                    # Roles ativas para selects
                    active_roles = Role.query.filter_by(active=True).order_by(Role.label).all()
                    return {"portal": settings, "user_modules": available, "active_roles": active_roles}
        except Exception:
            pass
        active_roles = Role.query.filter_by(active=True).order_by(Role.label).all()
        return {"portal": settings, "user_modules": set(), "active_roles": active_roles}
    except Exception:
        return {"portal": {}, "user_modules": set(), "active_roles": []}
    
# Lista de todos os módulos disponíveis
SYSTEM_MODULES = [
    {"key": "logs",        "label": "Logs de acesso",    "icon": "📋", "url": "/admin/logs"},
    {"key": "users",       "label": "Usuários",           "icon": "👥", "url": "/admin/users"},
    {"key": "groups",      "label": "Grupos",             "icon": "📁", "url": "/admin/groups"},
    {"key": "reports",     "label": "Relatórios",         "icon": "📊", "url": "/admin/reports"},
    {"key": "permissions", "label": "Permissões",         "icon": "🔑", "url": "/admin/permissions"},
    {"key": "roles",       "label": "Perfis RBAC",        "icon": "🎭", "url": "/admin/roles"},
    {"key": "settings",    "label": "Configurações",      "icon": "⚙️",  "url": "/admin/settings"},
]

app.config["SYSTEM_MODULES"] = SYSTEM_MODULES

@app.context_processor
def inject_modules():
    return {"SYSTEM_MODULES": SYSTEM_MODULES}

from routes import init_routes
init_routes(app, db, mail,
            User, Report, ReportRLS, Group, ReportGroup,
            Permission, RolePermission, AccessLog,
            PasswordResetCode, PortalSettings,
            RoleModulePermission, UserModulePermission, Role)

if __name__ == "__main__":
    with app.app_context():
        create_tables(db)
    app.run(debug=True, host="0.0.0.0", port=5000)