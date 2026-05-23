from flask import Blueprint, request, render_template, redirect, url_for, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from .helpers import check_module_access, get_user_modules, get_or_404

admin_groups_bp = Blueprint("admin_groups", __name__)

@admin_groups_bp.route("/admin/groups")
@jwt_required()
def admin_groups():
    ctx     = admin_groups_bp.ctx
    db      = ctx["db"]
    User    = ctx["User"]
    Group   = ctx["Group"]
    Report  = ctx["Report"]
    ReportGroup = ctx["ReportGroup"]
    user_id = int(get_jwt_identity())
    user    = db.session.get(User, user_id)
    if not user.is_admin and "groups" not in get_user_modules(ctx, user):
        return redirect(url_for("dashboard.dashboard"))
    groups  = Group.query.order_by(Group.created_at.desc()).all()
    reports = Report.query.filter_by(active=True).order_by(Report.name).all()
    group_report_ids = {
        g.id: [rg.report_id for rg in ReportGroup.query.filter_by(group_id=g.id).all()]
        for g in groups
    }
    return render_template("admin_groups.html", user=user, groups=groups,
                           reports=reports, group_report_ids=group_report_ids)

@admin_groups_bp.route("/admin/groups/create", methods=["POST"])
@jwt_required()
def admin_create_group():
    ctx         = admin_groups_bp.ctx
    db          = ctx["db"]
    User        = ctx["User"]
    Group       = ctx["Group"]
    ReportGroup = ctx["ReportGroup"]
    user_id     = int(get_jwt_identity())
    admin       = db.session.get(User, user_id)
    if not check_module_access(ctx, admin, "groups"):
        return jsonify({"error": "Sem permissão"}), 403
    data  = request.form
    group = Group(name=data["name"], description=data.get("description", ""), active=True)
    db.session.add(group)
    db.session.flush()
    for rid in request.form.getlist("report_ids"):
        db.session.add(ReportGroup(group_id=group.id, report_id=int(rid)))
    db.session.commit()
    return redirect(url_for("admin_groups.admin_groups"))

@admin_groups_bp.route("/admin/groups/edit/<int:group_id>", methods=["POST"])
@jwt_required()
def admin_edit_group(group_id):
    ctx         = admin_groups_bp.ctx
    db          = ctx["db"]
    User        = ctx["User"]
    Group       = ctx["Group"]
    ReportGroup = ctx["ReportGroup"]
    user_id     = int(get_jwt_identity())
    admin       = db.session.get(User, user_id)
    if not check_module_access(ctx, admin, "groups"):
        return jsonify({"error": "Sem permissão"}), 403
    group             = get_or_404(db, Group, group_id)
    data              = request.form
    group.name        = data["name"]
    group.description = data.get("description", "")
    ReportGroup.query.filter_by(group_id=group_id).delete()
    for rid in request.form.getlist("report_ids"):
        db.session.add(ReportGroup(group_id=group_id, report_id=int(rid)))
    db.session.commit()
    return redirect(url_for("admin_groups.admin_groups"))

@admin_groups_bp.route("/admin/groups/toggle/<int:group_id>", methods=["POST"])
@jwt_required()
def admin_toggle_group(group_id):
    ctx     = admin_groups_bp.ctx
    db      = ctx["db"]
    User    = ctx["User"]
    Group   = ctx["Group"]
    user_id = int(get_jwt_identity())
    admin   = db.session.get(User, user_id)
    if not check_module_access(ctx, admin, "groups"):
        return jsonify({"error": "Sem permissão"}), 403
    group        = get_or_404(db, Group, group_id)
    group.active = not group.active
    db.session.commit()
    return redirect(url_for("admin_groups.admin_groups"))

@admin_groups_bp.route("/admin/groups/delete/<int:group_id>", methods=["POST"])
@jwt_required()
def admin_delete_group(group_id):
    ctx            = admin_groups_bp.ctx
    db             = ctx["db"]
    User           = ctx["User"]
    Group          = ctx["Group"]
    ReportGroup    = ctx["ReportGroup"]
    Permission     = ctx["Permission"]
    RolePermission = ctx["RolePermission"]
    user_id        = int(get_jwt_identity())
    admin          = db.session.get(User, user_id)
    if not check_module_access(ctx, admin, "groups"):
        return jsonify({"error": "Sem permissão"}), 403
    ReportGroup.query.filter_by(group_id=group_id).delete()
    Permission.query.filter_by(group_id=group_id).delete()
    RolePermission.query.filter_by(group_id=group_id).delete()
    Group.query.filter_by(id=group_id).delete()
    db.session.commit()
    return redirect(url_for("admin_groups.admin_groups"))