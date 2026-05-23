from flask import Blueprint, request, render_template, redirect, url_for, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from .helpers import check_module_access, get_user_modules, get_or_404
from powerbi import clear_embed_cache

admin_reports_bp = Blueprint("admin_reports", __name__)

@admin_reports_bp.route("/admin/reports")
@jwt_required()
def admin_reports():
    ctx     = admin_reports_bp.ctx
    db      = ctx["db"]
    User    = ctx["User"]
    Report  = ctx["Report"]
    ReportRLS = ctx["ReportRLS"]
    user_id = int(get_jwt_identity())
    user    = db.session.get(User, user_id)
    if not user.is_admin and "reports" not in get_user_modules(ctx, user):
        return redirect(url_for("dashboard.dashboard"))
    reports = Report.query.order_by(Report.created_at.desc()).all()
    for r in reports:
        r.rls_list = ReportRLS.query.filter_by(report_id=r.id).all()
    return render_template("admin_reports.html", user=user, reports=reports)

@admin_reports_bp.route("/admin/reports/create", methods=["POST"])
@jwt_required()
def admin_create_report():
    ctx    = admin_reports_bp.ctx
    db     = ctx["db"]
    User   = ctx["User"]
    Report = ctx["Report"]
    user_id = int(get_jwt_identity())
    admin   = db.session.get(User, user_id)
    if not check_module_access(ctx, admin, "reports"):
        return jsonify({"error": "Sem permissão"}), 403
    data = request.form
    db.session.add(Report(
        name=data["name"], description=data.get("description", ""),
        report_id=data["report_id"], workspace_id=data["workspace_id"],
        has_rls=data.get("has_rls") == "on", active=True
    ))
    db.session.commit()
    return redirect(url_for("admin_reports.admin_reports"))

@admin_reports_bp.route("/admin/reports/edit/<int:report_id>", methods=["POST"])
@jwt_required()
def admin_edit_report(report_id):
    ctx    = admin_reports_bp.ctx
    db     = ctx["db"]
    User   = ctx["User"]
    Report = ctx["Report"]
    user_id = int(get_jwt_identity())
    admin   = db.session.get(User, user_id)
    if not check_module_access(ctx, admin, "reports"):
        return jsonify({"error": "Sem permissão"}), 403
    report = get_or_404(db, Report, report_id)
    data   = request.form
    report.name         = data["name"]
    report.description  = data.get("description", "")
    report.report_id    = data["report_id"]
    report.workspace_id = data["workspace_id"]
    report.has_rls      = data.get("has_rls") == "on"
    db.session.commit()
    clear_embed_cache(str(report.report_id))
    return redirect(url_for("admin_reports.admin_reports"))

@admin_reports_bp.route("/admin/reports/toggle/<int:report_id>", methods=["POST"])
@jwt_required()
def admin_toggle_report(report_id):
    ctx    = admin_reports_bp.ctx
    db     = ctx["db"]
    User   = ctx["User"]
    Report = ctx["Report"]
    user_id = int(get_jwt_identity())
    admin   = db.session.get(User, user_id)
    if not check_module_access(ctx, admin, "reports"):
        return jsonify({"error": "Sem permissão"}), 403
    report        = get_or_404(db, Report, report_id)
    report.active = not report.active
    db.session.commit()
    return redirect(url_for("admin_reports.admin_reports"))

@admin_reports_bp.route("/admin/reports/delete/<int:report_id>", methods=["POST"])
@jwt_required()
def admin_delete_report(report_id):
    ctx    = admin_reports_bp.ctx
    db     = ctx["db"]
    User   = ctx["User"]
    Report = ctx["Report"]
    Permission     = ctx["Permission"]
    RolePermission = ctx["RolePermission"]
    ReportGroup    = ctx["ReportGroup"]
    ReportRLS      = ctx["ReportRLS"]
    user_id = int(get_jwt_identity())
    admin   = db.session.get(User, user_id)
    if not check_module_access(ctx, admin, "reports"):
        return jsonify({"error": "Sem permissão"}), 403
    report = db.session.get(Report, report_id)
    pbi_id = report.report_id
    Permission.query.filter_by(report_id=report_id).delete()
    RolePermission.query.filter_by(report_id=report_id).delete()
    ReportGroup.query.filter_by(report_id=report_id).delete()
    ReportRLS.query.filter_by(report_id=report_id).delete()
    Report.query.filter_by(id=report_id).delete()
    db.session.commit()
    clear_embed_cache(str(pbi_id))
    return redirect(url_for("admin_reports.admin_reports"))

@admin_reports_bp.route("/admin/reports/<int:report_id>/rls/save", methods=["POST"])
@jwt_required()
def admin_save_rls(report_id):
    ctx       = admin_reports_bp.ctx
    db        = ctx["db"]
    User      = ctx["User"]
    Report    = ctx["Report"]
    ReportRLS = ctx["ReportRLS"]
    user_id   = int(get_jwt_identity())
    admin     = db.session.get(User, user_id)
    if not check_module_access(ctx, admin, "reports"):
        return jsonify({"error": "Sem permissão"}), 403
    report = get_or_404(db, Report, report_id)
    data   = request.form
    rls_id = data.get("rls_id")
    if rls_id:
        rls = db.session.get(ReportRLS, int(rls_id))
        rls.rule_name = data["rule_name"]; rls.system_role = data["system_role"]
        rls.role_name = data["role_name"]; rls.filter_source = data["filter_source"]
        rls.description = data.get("description", "")
    else:
        db.session.add(ReportRLS(
            report_id=report_id, rule_name=data["rule_name"],
            system_role=data["system_role"], role_name=data["role_name"],
            filter_source=data["filter_source"], description=data.get("description", "")
        ))
    report.has_rls = True
    db.session.commit()
    return redirect(url_for("admin_reports.admin_reports"))

@admin_reports_bp.route("/admin/reports/<int:report_id>/rls/<int:rls_id>/delete", methods=["POST"])
@jwt_required()
def admin_delete_rls(report_id, rls_id):
    ctx       = admin_reports_bp.ctx
    db        = ctx["db"]
    User      = ctx["User"]
    Report    = ctx["Report"]
    ReportRLS = ctx["ReportRLS"]
    user_id   = int(get_jwt_identity())
    admin     = db.session.get(User, user_id)
    if not check_module_access(ctx, admin, "reports"):
        return jsonify({"error": "Sem permissão"}), 403
    ReportRLS.query.filter_by(id=rls_id).delete()
    if ReportRLS.query.filter_by(report_id=report_id).count() == 0:
        report = db.session.get(Report, report_id)
        if report:
            report.has_rls = False
    db.session.commit()
    return redirect(url_for("admin_reports.admin_reports"))