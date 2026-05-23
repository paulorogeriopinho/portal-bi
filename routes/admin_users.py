from flask import Blueprint, request, render_template, redirect, url_for, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from auth import hash_password, validate_password
from sqlalchemy import or_
from .helpers import check_module_access, get_or_404

admin_users_bp = Blueprint("admin_users", __name__)

@admin_users_bp.route("/admin/users")
@jwt_required()
def admin_users():
    ctx     = admin_users_bp.ctx
    db      = ctx["db"]
    User    = ctx["User"]
    user_id = int(get_jwt_identity())
    user    = db.session.get(User, user_id)
    from .helpers import get_user_modules
    if not user.is_admin and "users" not in get_user_modules(ctx, user):
        return redirect(url_for("dashboard.dashboard"))
    q        = request.args.get("q", "").strip()
    f_role   = request.args.get("role", "")
    f_rev    = request.args.get("revenda", "").strip()
    f_dep    = request.args.get("departamento", "").strip()
    f_status = request.args.get("status", "")
    query    = User.query
    if q:
        query = query.filter(or_(User.name.ilike(f"%{q}%"), User.email.ilike(f"%{q}%")))
    if f_role:   query = query.filter_by(role=f_role)
    if f_rev:    query = query.filter(User.empresa_revenda.ilike(f"%{f_rev}%"))
    if f_dep:    query = query.filter(User.departamento.ilike(f"%{f_dep}%"))
    if f_status == "active":   query = query.filter_by(active=True)
    elif f_status == "inactive": query = query.filter_by(active=False)
    users = query.order_by(User.name).all()
    return render_template("admin_users.html", user=user, users=users,
                           q=q, f_role=f_role, f_rev=f_rev, f_dep=f_dep, f_status=f_status)

@admin_users_bp.route("/admin/users/create", methods=["POST"])
@jwt_required()
def admin_create_user():
    ctx     = admin_users_bp.ctx
    db      = ctx["db"]
    User    = ctx["User"]
    user_id = int(get_jwt_identity())
    admin   = db.session.get(User, user_id)
    if not check_module_access(ctx, admin, "users"):
        return jsonify({"error": "Sem permissão"}), 403
    data     = request.form
    password = data.get("password", "")
    valid, msg = validate_password(password)
    if not valid:
        users = User.query.order_by(User.name).all()
        return render_template("admin_users.html", user=admin, users=users,
                               q="", f_role="", f_rev="", f_dep="", f_status="",
                               form_error=msg, form_error_modal="modal-create",
                               form_error_user_id=None), 400
    db.session.add(User(
        name=data["name"], email=data["email"],
        password_hash=hash_password(password),
        is_admin=data.get("is_admin") == "on",
        role=data.get("role", "user"),
        empresa_revenda=data.get("empresa_revenda") or None,
        departamento=data.get("departamento") or None,
        active=True
    ))
    db.session.commit()
    return redirect(url_for("admin_users.admin_users"))

@admin_users_bp.route("/admin/users/edit/<int:target_id>", methods=["POST"])
@jwt_required()
def admin_edit_user(target_id):
    ctx     = admin_users_bp.ctx
    db      = ctx["db"]
    User    = ctx["User"]
    user_id = int(get_jwt_identity())
    admin   = db.session.get(User, user_id)
    if not check_module_access(ctx, admin, "users"):
        return jsonify({"error": "Sem permissão"}), 403
    data         = request.form
    new_password = data.get("password", "").strip()
    if new_password:
        valid, msg = validate_password(new_password)
        if not valid:
            users = User.query.order_by(User.name).all()
            return render_template("admin_users.html", user=admin, users=users,
                                   q="", f_role="", f_rev="", f_dep="", f_status="",
                                   form_error=msg, form_error_modal="modal-edit",
                                   form_error_user_id=target_id), 400
    u = get_or_404(db, User, target_id)
    u.name = data["name"]; u.email = data["email"]
    u.role = data.get("role", "user")
    u.empresa_revenda = data.get("empresa_revenda") or None
    u.departamento    = data.get("departamento") or None
    u.is_admin        = data.get("is_admin") == "on"
    u.active          = data.get("active") == "on"
    if new_password:
        u.password_hash = hash_password(new_password)
    db.session.commit()
    return redirect(url_for("admin_users.admin_users"))

@admin_users_bp.route("/admin/users/toggle/<int:target_id>", methods=["POST"])
@jwt_required()
def admin_toggle_user(target_id):
    ctx     = admin_users_bp.ctx
    db      = ctx["db"]
    User    = ctx["User"]
    user_id = int(get_jwt_identity())
    admin   = db.session.get(User, user_id)
    if not check_module_access(ctx, admin, "users"):
        return jsonify({"error": "Sem permissão"}), 403
    u        = get_or_404(db, User, target_id)
    u.active = not u.active
    db.session.commit()
    return redirect(url_for("admin_users.admin_users"))