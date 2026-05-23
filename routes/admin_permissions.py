from flask import Blueprint, request, render_template, redirect, url_for, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from .helpers import check_module_access, get_user_modules, get_or_404

admin_permissions_bp = Blueprint("admin_permissions", __name__)

MODULES_LIST = [
    {"key": "logs",        "label": "Logs de acesso", "icon": "📋"},
    {"key": "users",       "label": "Usuários",        "icon": "👥"},
    {"key": "groups",      "label": "Grupos",          "icon": "📁"},
    {"key": "reports",     "label": "Relatórios",      "icon": "📊"},
    {"key": "permissions", "label": "Permissões",      "icon": "🔑"},
    {"key": "roles",       "label": "Perfis RBAC",     "icon": "🎭"},
    {"key": "settings",    "label": "Configurações",   "icon": "⚙️"},
]

@admin_permissions_bp.route("/admin/permissions")
@jwt_required()
def admin_permissions():
    ctx     = admin_permissions_bp.ctx
    db      = ctx["db"]
    User    = ctx["User"]
    user_id = int(get_jwt_identity())
    user    = db.session.get(User, user_id)
    if not user.is_admin and "permissions" not in get_user_modules(ctx, user):
        return redirect(url_for("dashboard.dashboard"))
    users = User.query.filter_by(is_admin=False, active=True).order_by(User.name).all()
    return render_template("admin_permissions.html", user=user, users=users)

@admin_permissions_bp.route("/admin/permissions/toggle", methods=["POST"])
@jwt_required()
def toggle_permission():
    ctx        = admin_permissions_bp.ctx
    db         = ctx["db"]
    User       = ctx["User"]
    Permission = ctx["Permission"]
    user_id    = int(get_jwt_identity())
    admin      = db.session.get(User, user_id)
    if not check_module_access(ctx, admin, "permissions"):
        return jsonify({"error": "Sem permissão"}), 403
    data       = request.json
    target_uid = data["user_id"]
    group_id   = data.get("group_id")
    report_id  = data.get("report_id")
    if group_id:
        perm = Permission.query.filter_by(user_id=target_uid, group_id=group_id, report_id=None).first()
    else:
        perm = Permission.query.filter_by(user_id=target_uid, report_id=report_id, group_id=None).first()
    if perm:
        db.session.delete(perm)
        db.session.commit()
        return jsonify({"status": "removed"})
    db.session.add(Permission(
        user_id=target_uid,
        group_id=group_id   if group_id  else None,
        report_id=report_id if report_id else None
    ))
    db.session.commit()
    return jsonify({"status": "added"})

@admin_permissions_bp.route("/admin/permissions/toggle-module", methods=["POST"])
@jwt_required()
def toggle_user_module():
    ctx                  = admin_permissions_bp.ctx
    db                   = ctx["db"]
    User                 = ctx["User"]
    UserModulePermission = ctx["UserModulePermission"]
    user_id              = int(get_jwt_identity())
    admin                = db.session.get(User, user_id)
    if not check_module_access(ctx, admin, "permissions"):
        return jsonify({"error": "Sem permissão"}), 403
    data      = request.json
    target_id = data["user_id"]
    module    = data["module"]
    perm      = UserModulePermission.query.filter_by(user_id=target_id, module=module).first()
    if perm:
        db.session.delete(perm)
        db.session.commit()
        return jsonify({"status": "removed"})
    db.session.add(UserModulePermission(user_id=target_id, module=module))
    db.session.commit()
    return jsonify({"status": "added"})

@admin_permissions_bp.route("/admin/permissions/user/<int:target_id>")
@jwt_required()
def get_user_permissions(target_id):
    ctx                  = admin_permissions_bp.ctx
    db                   = ctx["db"]
    User                 = ctx["User"]
    Group                = ctx["Group"]
    Report               = ctx["Report"]
    Permission           = ctx["Permission"]
    RolePermission       = ctx["RolePermission"]
    RoleModulePermission = ctx["RoleModulePermission"]
    UserModulePermission = ctx["UserModulePermission"]
    user_id              = int(get_jwt_identity())
    admin                = db.session.get(User, user_id)
    if not check_module_access(ctx, admin, "permissions"):
        return jsonify({"error": "Sem permissão"}), 403
    target = get_or_404(db, User, target_id)

    ind_group_ids  = {p.group_id  for p in Permission.query.filter_by(user_id=target_id, report_id=None).all() if p.group_id}
    ind_report_ids = {p.report_id for p in Permission.query.filter_by(user_id=target_id, group_id=None).all() if p.report_id}
    ind_mod_keys   = {um.module   for um in UserModulePermission.query.filter_by(user_id=target_id).all()}
    role_group_ids  = {rp.group_id  for rp in RolePermission.query.filter_by(role=target.role, report_id=None).all() if rp.group_id}
    role_report_ids = {rp.report_id for rp in RolePermission.query.filter_by(role=target.role, group_id=None).all() if rp.report_id}
    role_mod_keys   = {rm.module    for rm in RoleModulePermission.query.filter_by(role=target.role).all()}

    groups  = Group.query.filter_by(active=True).order_by(Group.name).all()
    reports = Report.query.filter_by(active=True).order_by(Report.name).all()

    return jsonify({
        "user": {
            "id": target.id, "name": target.name, "role": target.role,
            "empresa_revenda": target.empresa_revenda or "—",
            "departamento":    target.departamento or "—",
            "ind_count": len(ind_group_ids) + len(ind_report_ids) + len(ind_mod_keys)
        },
        "groups":  [{"id": g.id, "name": g.name,
                     "source": "role" if g.id in role_group_ids else ("individual" if g.id in ind_group_ids else None)}
                    for g in groups],
        "reports": [{"id": r.id, "name": r.name,
                     "source": "role" if r.id in role_report_ids else ("individual" if r.id in ind_report_ids else None)}
                    for r in reports],
        "modules": [{"key": m["key"], "label": m["label"], "icon": m["icon"],
                     "source": "role" if m["key"] in role_mod_keys else ("individual" if m["key"] in ind_mod_keys else None)}
                    for m in MODULES_LIST],
    })

@admin_permissions_bp.route("/admin/permissions/role/<string:role>")
@jwt_required()
def get_role_permissions(role):
    ctx                  = admin_permissions_bp.ctx
    db                   = ctx["db"]
    User                 = ctx["User"]
    Group                = ctx["Group"]
    Report               = ctx["Report"]
    Role                 = ctx["Role"]
    RolePermission       = ctx["RolePermission"]
    RoleModulePermission = ctx["RoleModulePermission"]
    user_id              = int(get_jwt_identity())
    admin                = db.session.get(User, user_id)
    if not admin.is_admin:
        return jsonify({"error": "Sem permissão"}), 403

    role_group_ids  = {rp.group_id  for rp in RolePermission.query.filter_by(role=role, report_id=None).all() if rp.group_id}
    role_report_ids = {rp.report_id for rp in RolePermission.query.filter_by(role=role, group_id=None).all() if rp.report_id}
    role_mod_keys   = {rm.module    for rm in RoleModulePermission.query.filter_by(role=role).all()}
    groups          = Group.query.filter_by(active=True).order_by(Group.name).all()
    reports         = Report.query.filter_by(active=True).order_by(Report.name).all()
    role_obj        = Role.query.filter_by(key=role).first()
    user_count      = User.query.filter_by(role=role, active=True).count()

    return jsonify({
        "role": role,
        "label": role_obj.label if role_obj else role,
        "user_count": user_count,
        "groups":  [{"id": g.id, "name": g.name, "active": g.id in role_group_ids} for g in groups],
        "reports": [{"id": r.id, "name": r.name, "active": r.id in role_report_ids} for r in reports],
        "modules": [{"key": m["key"], "label": m["label"], "icon": m["icon"], "active": m["key"] in role_mod_keys} for m in MODULES_LIST],
    })