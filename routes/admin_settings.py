from flask import Blueprint, request, render_template, redirect, url_for
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime, timedelta, timezone
from .helpers import check_module_access

BRASILIA          = timezone(timedelta(hours=-3))
admin_settings_bp = Blueprint("admin_settings", __name__)

@admin_settings_bp.route("/admin/settings", methods=["GET", "POST"])
@jwt_required()
def admin_settings():
    ctx            = admin_settings_bp.ctx
    db             = ctx["db"]
    User           = ctx["User"]
    PortalSettings = ctx["PortalSettings"]
    user_id        = int(get_jwt_identity())
    user           = db.session.get(User, user_id)
    if not check_module_access(ctx, user, "settings"):
        return redirect(url_for("dashboard.dashboard"))

    if request.method == "POST":
        data = request.form
        for key in ["company_name", "company_logo", "accent_color", "portal_name", "white_label"]:
            setting = PortalSettings.query.filter_by(key=key).first()
            if setting:
                setting.value      = data.get(key, "")
                setting.updated_at = datetime.now(BRASILIA).replace(tzinfo=None)
            else:
                db.session.add(PortalSettings(key=key, value=data.get(key, "")))
        db.session.commit()
        return redirect(url_for("admin_settings.admin_settings"))

    settings = {s.key: s.value for s in PortalSettings.query.all()}
    return render_template("admin_settings.html", user=user, settings=settings)