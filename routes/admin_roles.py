from flask import Blueprint, request, render_template, redirect, url_for, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from .helpers import check_module_access, get_or_404

admin_roles_bp = Blueprint("admin_roles", __name__)

@admin_roles_bp.route("/admin/roles")
@jwt_required()
def admin_roles():
    ctx     = admin_roles_bp.ctx
    db      = ctx["db"]
    User    = ctx["User"]
    user_id = int(get_jwt_identity())
    user    = db.session.get(User, user_id)
    if not check_module_access(ctx, user, "roles"):
        return redirect(url_for("dashboard.dashboard"))
    return render_template("admin_roles.html", user=user)

@admin_roles_bp.route("/admin/roles/manage")
@jwt_required()
def admin_roles_manage():
    ctx     = admin_roles_bp.ctx
    db      = ctx["db"]
    User    = ctx["User"]
    Role    = ctx["Role"]
    user_id = int(get_jwt_identity())
    user    = db.session.get(User, user_id)
    if not check_module_access(ctx, user, "roles"):
        return redirect(url_for("dashboard.dashboard"))
    roles = Role.query.order_by(Role.created_at.desc()).all()
    return render_template("admin_roles_manage.html", user=user, roles=roles)

@admin_roles_bp.route("/admin/roles/manage/create", methods=["POST"])
@jwt_required()
def admin_roles_manage_create():
    ctx     = admin_roles_bp.ctx
    db      = ctx["db"]
    User    = ctx["User"]
    Role    = ctx["Role"]
    user_id = int(get_jwt_identity())
    admin   = db.session.get(User, user_id)
    if not check_module_access(ctx, admin, "roles"):
        return jsonify({"error": "Sem permissão"}), 403
    data = request.form
    key  = data["key"].lower().strip().replace(" ", "_")
    if Role.query.filter_by(key=key).first():
        return render_template("admin_roles_manage.html", user=admin,
                               roles=Role.query.order_by(Role.created_at.desc()).all(),
                               error=f"A chave '{key}' já existe.")
    PALETTE     = ['#0F6E56','#1E40AF','#92400E','#5B21B6','#065F46','#9D174D','#1E3A5F','#713F12','#166534','#7C3AED','#0369A1','#B45309']
    used_colors = {r.color for r in Role.query.all()}
    available   = [c for c in PALETTE if c not in used_colors]
    color       = available[0] if available else PALETTE[len(Role.query.all()) % len(PALETTE)]
    db.session.add(Role(key=key, label=data["label"],
                        description=data.get("description", ""),
                        color=color, active=True))
    db.session.commit()
    return redirect(url_for("admin_roles.admin_roles_manage"))

@admin_roles_bp.route("/admin/roles/manage/edit/<int:role_id>", methods=["POST"])
@jwt_required()
def admin_roles_manage_edit(role_id):
    ctx     = admin_roles_bp.ctx
    db      = ctx["db"]
    User    = ctx["User"]
    Role    = ctx["Role"]
    user_id = int(get_jwt_identity())
    admin   = db.session.get(User, user_id)
    if not check_module_access(ctx, admin, "roles"):
        return jsonify({"error": "Sem permissão"}), 403
    role             = get_or_404(db, Role, role_id)
    data             = request.form
    role.label       = data["label"]
    role.description = data.get("description", "")
    role.color       = data.get("color", role.color)
    role.active      = data.get("active") == "on"
    db.session.commit()
    return redirect(url_for("admin_roles.admin_roles_manage"))

@admin_roles_bp.route("/admin/roles/manage/delete/<int:role_id>", methods=["POST"])
@jwt_required()
def admin_roles_manage_delete(role_id):
    ctx                  = admin_roles_bp.ctx
    db                   = ctx["db"]
    User                 = ctx["User"]
    Role                 = ctx["Role"]
    RolePermission       = ctx["RolePermission"]
    RoleModulePermission = ctx["RoleModulePermission"]
    user_id              = int(get_jwt_identity())
    admin                = db.session.get(User, user_id)
    if not check_module_access(ctx, admin, "roles"):
        return jsonify({"error": "Sem permissão"}), 403
    role  = get_or_404(db, Role, role_id)
    count = User.query.filter_by(role=role.key).count()
    if count > 0:
        return render_template("admin_roles_manage.html", user=admin,
                               roles=Role.query.order_by(Role.created_at.desc()).all(),
                               error=f"Não é possível excluir: {count} usuário(s) usam este perfil.")
    RolePermission.query.filter_by(role=role.key).delete()
    RoleModulePermission.query.filter_by(role=role.key).delete()
    db.session.delete(role)
    db.session.commit()
    return redirect(url_for("admin_roles.admin_roles_manage"))

@admin_roles_bp.route("/admin/roles/toggle", methods=["POST"])
@jwt_required()
def toggle_role_permission():
    ctx            = admin_roles_bp.ctx
    db             = ctx["db"]
    User           = ctx["User"]
    RolePermission = ctx["RolePermission"]
    user_id        = int(get_jwt_identity())
    admin          = db.session.get(User, user_id)
    if not check_module_access(ctx, admin, "roles"):
        return jsonify({"error": "Sem permissão"}), 403
    data      = request.json
    role      = data["role"]
    group_id  = data.get("group_id")
    report_id = data.get("report_id")
    if group_id:
        perm = RolePermission.query.filter_by(role=role, group_id=group_id, report_id=None).first()
    else:
        perm = RolePermission.query.filter_by(role=role, report_id=report_id, group_id=None).first()
    if perm:
        db.session.delete(perm)
        db.session.commit()
        return jsonify({"status": "removed"})
    db.session.add(RolePermission(
        role=role,
        group_id=group_id   if group_id  else None,
        report_id=report_id if report_id else None
    ))
    db.session.commit()
    return jsonify({"status": "added"})

@admin_roles_bp.route("/admin/roles/toggle-module", methods=["POST"])
@jwt_required()
def toggle_role_module():
    ctx                  = admin_roles_bp.ctx
    db                   = ctx["db"]
    User                 = ctx["User"]
    RoleModulePermission = ctx["RoleModulePermission"]
    user_id              = int(get_jwt_identity())
    admin                = db.session.get(User, user_id)
    if not check_module_access(ctx, admin, "roles"):
        return jsonify({"error": "Sem permissão"}), 403
    data   = request.json
    role   = data["role"]
    module = data["module"]
    perm   = RoleModulePermission.query.filter_by(role=role, module=module).first()
    if perm:
        db.session.delete(perm)
        db.session.commit()
        return jsonify({"status": "removed"})
    db.session.add(RoleModulePermission(role=role, module=module))
    db.session.commit()
    return jsonify({"status": "added"})