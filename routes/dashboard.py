from flask import Blueprint, render_template, redirect, url_for, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from .helpers import get_user_reports, can_access_report
from powerbi import get_embed_token
from datetime import datetime, timedelta, timezone

BRASILIA     = timezone(timedelta(hours=-3))
dashboard_bp = Blueprint("dashboard", __name__)

@dashboard_bp.route("/dashboard")
@jwt_required()
def dashboard():
    ctx     = dashboard_bp.ctx
    db      = ctx["db"]
    User    = ctx["User"]
    user_id = int(get_jwt_identity())
    user    = db.session.get(User, user_id)
    groups_data, loose_reports, fav_reports, fav_ids = get_user_reports(ctx, user)
    return render_template("dashboard.html", user=user,
                           groups_data=groups_data, loose_reports=loose_reports,
                           fav_reports=fav_reports, fav_ids=fav_ids)

@dashboard_bp.route("/report/<int:report_id>")
@jwt_required()
def view_report(report_id):
    ctx        = dashboard_bp.ctx
    db         = ctx["db"]
    User       = ctx["User"]
    Report     = ctx["Report"]
    ReportRLS  = ctx["ReportRLS"]
    AccessLog  = ctx["AccessLog"]
    user_id    = int(get_jwt_identity())
    user       = db.session.get(User, user_id)
    report     = db.session.get(Report, report_id)
    if report is None:
        return redirect(url_for("dashboard.dashboard"))
    if not can_access_report(ctx, user, report_id):
        return redirect(url_for("dashboard.dashboard"))
    db.session.add(AccessLog(
        user_id=user_id, report_id=report_id,
        ip_address=request.remote_addr,
        accessed_at=datetime.now(BRASILIA).replace(tzinfo=None)
    ))
    db.session.commit()
    rls_configs = ReportRLS.query.filter_by(report_id=report_id).all()
    embed_data  = get_embed_token(
        report.workspace_id, report.report_id,
        user=user, has_rls=report.has_rls, rls_configs=rls_configs
    )
    groups_data, loose_reports, fav_reports, fav_ids = get_user_reports(ctx, user)
    return render_template("report.html", user=user, report=report, embed=embed_data,
                           groups_data=groups_data, loose_reports=loose_reports,
                           fav_reports=fav_reports, fav_ids=fav_ids)

@dashboard_bp.route("/favorites/toggle/<int:report_id>", methods=["POST"])
@jwt_required()
def toggle_favorite(report_id):
    ctx         = dashboard_bp.ctx
    db          = ctx["db"]
    UserFavorite = ctx["UserFavorite"]
    user_id     = int(get_jwt_identity())
    fav         = UserFavorite.query.filter_by(user_id=user_id, report_id=report_id).first()
    if fav:
        db.session.delete(fav)
        db.session.commit()
        return jsonify({"status": "removed"})
    max_pos = db.session.query(db.func.max(UserFavorite.position)).filter_by(user_id=user_id).scalar() or 0
    db.session.add(UserFavorite(user_id=user_id, report_id=report_id, position=max_pos + 1))
    db.session.commit()
    return jsonify({"status": "added"})

@dashboard_bp.route("/favorites/reorder", methods=["POST"])
@jwt_required()
def reorder_favorites():
    ctx          = dashboard_bp.ctx
    db           = ctx["db"]
    UserFavorite = ctx["UserFavorite"]
    user_id      = int(get_jwt_identity())
    ids          = request.json.get("ids", [])
    for i, rid in enumerate(ids):
        fav = UserFavorite.query.filter_by(user_id=user_id, report_id=rid).first()
        if fav:
            fav.position = i
    db.session.commit()
    return jsonify({"status": "ok"})