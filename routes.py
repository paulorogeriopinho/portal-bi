from flask import request, jsonify, render_template, redirect, url_for, make_response
from flask_jwt_extended import (
    create_access_token, jwt_required, get_jwt_identity,
    set_access_cookies, unset_jwt_cookies
)
from flask_mail import Message
from auth import hash_password, check_password
from powerbi import get_embed_token
from datetime import datetime, timedelta
from sqlalchemy import or_
import random
import string

def init_routes(app, db, mail,
                User, Report, ReportRLS, Group, ReportGroup,
                Permission, RolePermission, AccessLog,
                PasswordResetCode, PortalSettings,
                RoleModulePermission, UserModulePermission,
                Role, UserFavorite):
    
    # ── Helpers ──────────────────────────────────────────────────

    def get_user_modules(user):
        """Retorna set de módulos que o usuário pode acessar."""
        if user.is_admin:
            return {m["key"] for m in app.config["SYSTEM_MODULES"]}
        # Via role
        role_mods = {rm.module for rm in
                     RoleModulePermission.query.filter_by(role=user.role).all()}
        # Via permissão individual
        user_mods = {um.module for um in
                     UserModulePermission.query.filter_by(user_id=user.id).all()}
        return role_mods | user_mods

    def require_module(module_key):
        """Decorator que verifica acesso ao módulo."""
        from functools import wraps
        def decorator(f):
            @wraps(f)
            def decorated(*args, **kwargs):
                from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
                verify_jwt_in_request()
                uid  = int(get_jwt_identity())
                user = User.query.get(uid)
                if not user or not user.active:
                    return redirect(url_for("login"))
                if user.is_admin or module_key in get_user_modules(user):
                    return f(*args, **kwargs)
                return redirect(url_for("dashboard"))
            return decorated
        return decorator
    
    def get_user_reports(user):
        if user.is_admin:
            groups = Group.query.filter_by(active=True).order_by(Group.name).all()
            all_grouped_ids = [rg.report_id for rg in ReportGroup.query.all()]
            loose = Report.query.filter_by(active=True).filter(
                ~Report.id.in_(all_grouped_ids) if all_grouped_ids else True
            ).all()
        else:
            role_group_ids = [
                rp.group_id for rp in
                RolePermission.query.filter_by(role=user.role, report_id=None).all()
                if rp.group_id
            ]
            user_group_ids = [
                p.group_id for p in
                Permission.query.filter_by(user_id=user.id, report_id=None).all()
                if p.group_id
            ]
            all_group_ids = list(set(role_group_ids + user_group_ids))
            groups = Group.query.filter(
                Group.id.in_(all_group_ids), Group.active == True
            ).order_by(Group.name).all() if all_group_ids else []

            role_report_ids = [
                rp.report_id for rp in
                RolePermission.query.filter_by(role=user.role, group_id=None).all()
                if rp.report_id
            ]
            user_report_ids = [
                p.report_id for p in
                Permission.query.filter_by(user_id=user.id, group_id=None).all()
                if p.report_id
            ]
            all_report_ids = list(set(role_report_ids + user_report_ids))

            grouped_ids = [
                rg.report_id for rg in
                ReportGroup.query.filter(ReportGroup.group_id.in_(all_group_ids)).all()
            ] if all_group_ids else []
            loose_ids = [rid for rid in all_report_ids if rid not in grouped_ids]
            loose = Report.query.filter(
                Report.id.in_(loose_ids), Report.active == True
            ).all() if loose_ids else []

        # Favoritos ordenados por position
        favs = UserFavorite.query.filter_by(user_id=user.id)\
            .order_by(UserFavorite.position).all()
        fav_ids = [f.report_id for f in favs]

        # Coleta todos os report_ids que o usuário pode ver
        all_visible = set()
        all_visible.update(r.id for r in loose)
        for g in groups:
            rg_ids = [rg.report_id for rg in ReportGroup.query.filter_by(group_id=g.id).all()]
            all_visible.update(rg_ids)

        # Favoritos que o usuário ainda tem acesso
        fav_reports = []
        for fid in fav_ids:
            if fid in all_visible or user.is_admin:
                r = Report.query.filter_by(id=fid, active=True).first()
                if r:
                    fav_reports.append(r)

        groups_data = []
        for g in groups:
            rg_ids  = [rg.report_id for rg in ReportGroup.query.filter_by(group_id=g.id).all()]
            reports = Report.query.filter(
                Report.id.in_(rg_ids), Report.active == True
            ).all() if rg_ids else []
            if reports:
                groups_data.append({"group": g, "reports": reports})

        return groups_data, loose, fav_reports, fav_ids

    def can_access_report(user, report_id):
        """Verifica se usuário pode acessar um relatório."""
        if user.is_admin:
            return True
        # Via permissão individual
        if Permission.query.filter_by(user_id=user.id, report_id=report_id, group_id=None).first():
            return True
        # Via permissão de role individual
        if RolePermission.query.filter_by(role=user.role, report_id=report_id, group_id=None).first():
            return True
        # Via grupo (individual ou role)
        rg_entries = ReportGroup.query.filter_by(report_id=report_id).all()
        group_ids  = [rg.group_id for rg in rg_entries]
        if group_ids:
            if Permission.query.filter(
                Permission.user_id == user.id,
                Permission.group_id.in_(group_ids),
                Permission.report_id == None
            ).first():
                return True
            if RolePermission.query.filter(
                RolePermission.role == user.role,
                RolePermission.group_id.in_(group_ids),
                RolePermission.report_id == None
            ).first():
                return True
        return False

    def check_module_access(user, module_key):
        """Retorna True se o usuário tem acesso ao módulo."""
        if user.is_admin:
            return True
        # settings é exclusivo do admin
        if module_key == "settings":
            return False
        return module_key in get_user_modules(user)

    # ── Auth ─────────────────────────────────────────────────────

    @app.route("/")
    def index():
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return render_template("login.html")
        data = request.form
        user = User.query.filter_by(email=data["email"], active=True).first()
        if not user or not check_password(data["password"], user.password_hash):
            return render_template("login.html", error="Email ou senha incorretos.")
        token    = create_access_token(identity=str(user.id))
        response = make_response(redirect(url_for("dashboard")))
        set_access_cookies(response, token)
        return response

    @app.route("/logout")
    def logout():
        response = make_response(redirect(url_for("login")))
        unset_jwt_cookies(response)
        return response

    @app.route("/setup", methods=["GET", "POST"])
    def setup():
        if User.query.count() > 0:
            return redirect(url_for("login"))
        if request.method == "POST":
            data  = request.form
            admin = User(
                name=data["name"], email=data["email"],
                password_hash=hash_password(data["password"]),
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
            return redirect(url_for("login"))
        return render_template("setup.html")

    # ── Dashboard ─────────────────────────────────────────────────

    @app.route("/dashboard")
    @jwt_required()
    def dashboard():
        user_id = int(get_jwt_identity())
        user    = User.query.get(user_id)
        groups_data, loose_reports, fav_reports, fav_ids = get_user_reports(user)
        return render_template("dashboard.html",
                               user=user,
                               groups_data=groups_data,
                               loose_reports=loose_reports,
                               fav_reports=fav_reports,
                               fav_ids=fav_ids)

    @app.route("/report/<int:report_id>")
    @jwt_required()
    def view_report(report_id):
        user_id = int(get_jwt_identity())
        user    = User.query.get(user_id)
        report  = Report.query.get_or_404(report_id)

        if not can_access_report(user, report_id):
            return redirect(url_for("dashboard"))

        log = AccessLog(
            user_id=user_id, report_id=report_id,
            ip_address=request.remote_addr,
            accessed_at=datetime.utcnow()
        )
        db.session.add(log)
        db.session.commit()

        rls_configs = ReportRLS.query.filter_by(report_id=report_id).all()
        embed_data  = get_embed_token(
            report.workspace_id, report.report_id,
            user=user, has_rls=report.has_rls, rls_configs=rls_configs
        )

        # Dados para a sidebar
        groups_data, loose_reports, fav_reports, fav_ids = get_user_reports(user)

        return render_template("report.html",
                               user=user,
                               report=report,
                               embed=embed_data,
                               groups_data=groups_data,
                               loose_reports=loose_reports,
                               fav_reports=fav_reports,
                               fav_ids=fav_ids)

    # ── Admin Users ───────────────────────────────────────────────

    @app.route("/admin/users")
    @jwt_required()
    def admin_users():
        user_id = int(get_jwt_identity())
        user    = User.query.get(user_id)
        if not user.is_admin and "users" not in get_user_modules(user):
            return redirect(url_for("dashboard"))

        # Filtros
        q       = request.args.get("q", "").strip()
        f_role  = request.args.get("role", "")
        f_rev   = request.args.get("revenda", "").strip()
        f_dep   = request.args.get("departamento", "").strip()
        f_status= request.args.get("status", "")

        query = User.query
        if q:
            query = query.filter(or_(
                User.name.ilike(f"%{q}%"),
                User.email.ilike(f"%{q}%")
            ))
        if f_role:
            query = query.filter_by(role=f_role)
        if f_rev:
            query = query.filter(User.empresa_revenda.ilike(f"%{f_rev}%"))
        if f_dep:
            query = query.filter(User.departamento.ilike(f"%{f_dep}%"))
        if f_status == "active":
            query = query.filter_by(active=True)
        elif f_status == "inactive":
            query = query.filter_by(active=False)

        users = query.order_by(User.name).all()
        return render_template("admin_users.html",
                               user=user, users=users,
                               q=q, f_role=f_role, f_rev=f_rev,
                               f_dep=f_dep, f_status=f_status)

    @app.route("/admin/users/create", methods=["POST"])
    @jwt_required()
    def admin_create_user():
        user_id = int(get_jwt_identity())
        admin   = User.query.get(user_id)
        if not check_module_access(admin, "users"):
            return jsonify({"error": "Sem permissão"}), 403
        data     = request.form
        new_user = User(
            name            = data["name"],
            email           = data["email"],
            password_hash   = hash_password(data["password"]),
            is_admin        = data.get("is_admin") == "on",
            role            = data.get("role", "user"),
            empresa_revenda = data.get("empresa_revenda") or None,
            departamento    = data.get("departamento") or None,
            #client_id       = int(data["client_id"]) if data.get("client_id") else None,   -> Campo não está sendo utilizado, pode ser removido no futuro
            active          = True
        )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("admin_users"))

    @app.route("/admin/users/edit/<int:target_id>", methods=["POST"])
    @jwt_required()
    def admin_edit_user(target_id):
        user_id = int(get_jwt_identity())
        admin   = User.query.get(user_id)
        if not check_module_access(admin, "users"):
            return jsonify({"error": "Sem permissão"}), 403
        data = request.form
        u    = User.query.get_or_404(target_id)
        u.name            = data["name"]
        u.email           = data["email"]
        u.role            = data.get("role", "user")
        u.empresa_revenda = data.get("empresa_revenda") or None
        u.departamento    = data.get("departamento") or None
        u.is_admin        = data.get("is_admin") == "on"
        u.active          = data.get("active") == "on"
        #u.client_id       = int(data["client_id"]) if data.get("client_id") else None   -> Campo não está sendo utilizado, pode ser removido no futuro
        if data.get("password"):
            u.password_hash = hash_password(data["password"])
        db.session.commit()
        return redirect(url_for("admin_users"))

    @app.route("/admin/users/toggle/<int:target_id>", methods=["POST"])
    @jwt_required()
    def admin_toggle_user(target_id):
        user_id = int(get_jwt_identity())
        admin   = User.query.get(user_id)
        if not check_module_access(admin, "users"):
            return jsonify({"error": "Sem permissão"}), 403
        u        = User.query.get_or_404(target_id)
        u.active = not u.active
        db.session.commit()
        return redirect(url_for("admin_users"))

    # ── Admin Reports ─────────────────────────────────────────────

    @app.route("/admin/reports")
    @jwt_required()
    def admin_reports():
        user_id = int(get_jwt_identity())
        user    = User.query.get(user_id)
        if not user.is_admin and "reports" not in get_user_modules(user):
            return redirect(url_for("dashboard"))
        reports = Report.query.order_by(Report.created_at.desc()).all()
        for r in reports:
            r.rls_list = ReportRLS.query.filter_by(report_id=r.id).all()
        return render_template("admin_reports.html", user=user, reports=reports)

    @app.route("/admin/reports/create", methods=["POST"])
    @jwt_required()
    def admin_create_report():
        user_id = int(get_jwt_identity())
        admin   = User.query.get(user_id)
        if not check_module_access(admin, "reports"):
            return jsonify({"error": "Sem permissão"}), 403
        data = request.form
        new_report = Report(
            name         = data["name"],
            description  = data.get("description", ""),
            report_id    = data["report_id"],
            workspace_id = data["workspace_id"],
            has_rls      = data.get("has_rls") == "on",
            active       = True
        )
        db.session.add(new_report)
        db.session.commit()
        return redirect(url_for("admin_reports"))

    @app.route("/admin/reports/edit/<int:report_id>", methods=["POST"])
    @jwt_required()
    def admin_edit_report(report_id):
        user_id = int(get_jwt_identity())
        admin   = User.query.get(user_id)
        if not check_module_access(admin, "reports"):
            return jsonify({"error": "Sem permissão"}), 403
        report              = Report.query.get_or_404(report_id)
        data                = request.form
        report.name         = data["name"]
        report.description  = data.get("description", "")
        report.report_id    = data["report_id"]
        report.workspace_id = data["workspace_id"]
        report.has_rls      = data.get("has_rls") == "on"
        db.session.commit()
        return redirect(url_for("admin_reports"))

    @app.route("/admin/reports/toggle/<int:report_id>", methods=["POST"])
    @jwt_required()
    def admin_toggle_report(report_id):
        user_id = int(get_jwt_identity())
        admin   = User.query.get(user_id)
        if not check_module_access(admin, "reports"):
            return jsonify({"error": "Sem permissão"}), 403
        report        = Report.query.get_or_404(report_id)
        report.active = not report.active
        db.session.commit()
        return redirect(url_for("admin_reports"))

    @app.route("/admin/reports/delete/<int:report_id>", methods=["POST"])
    @jwt_required()
    def admin_delete_report(report_id):
        user_id = int(get_jwt_identity())
        admin   = User.query.get(user_id)
        if not check_module_access(admin, "reports"):
            return jsonify({"error": "Sem permissão"}), 403
        Permission.query.filter_by(report_id=report_id).delete()
        RolePermission.query.filter_by(report_id=report_id).delete()
        ReportGroup.query.filter_by(report_id=report_id).delete()
        ReportRLS.query.filter_by(report_id=report_id).delete()
        Report.query.filter_by(id=report_id).delete()
        db.session.commit()
        return redirect(url_for("admin_reports"))

    @app.route("/admin/reports/<int:report_id>/rls/save", methods=["POST"])
    @jwt_required()
    def admin_save_rls(report_id):
        user_id = int(get_jwt_identity())
        admin   = User.query.get(user_id)
        if not check_module_access(admin, "reports"):
            return jsonify({"error": "Sem permissão"}), 403
        report = Report.query.get_or_404(report_id)
        data   = request.form
        rls_id = data.get("rls_id")
        if rls_id:
            rls               = ReportRLS.query.get(int(rls_id))
            rls.rule_name     = data["rule_name"]
            rls.system_role   = data["system_role"]
            rls.role_name     = data["role_name"]
            rls.filter_source = data["filter_source"]
            rls.description   = data.get("description", "")
        else:
            rls = ReportRLS(
                report_id     = report_id,
                rule_name     = data["rule_name"],
                system_role   = data["system_role"],
                role_name     = data["role_name"],
                filter_source = data["filter_source"],
                description   = data.get("description", "")
            )
            db.session.add(rls)
        report.has_rls = True
        db.session.commit()
        return redirect(url_for("admin_reports"))

    @app.route("/admin/reports/<int:report_id>/rls/<int:rls_id>/delete", methods=["POST"])
    @jwt_required()
    def admin_delete_rls(report_id, rls_id):
        user_id = int(get_jwt_identity())
        admin   = User.query.get(user_id)
        if not check_module_access(admin, "reports"):
            return jsonify({"error": "Sem permissão"}), 403
        ReportRLS.query.filter_by(id=rls_id).delete()
        if ReportRLS.query.filter_by(report_id=report_id).count() == 0:
            report         = Report.query.get(report_id)
            report.has_rls = False
        db.session.commit()
        return redirect(url_for("admin_reports"))

    # ── Admin Groups ──────────────────────────────────────────────

    @app.route("/admin/groups")
    @jwt_required()
    def admin_groups():
        user_id = int(get_jwt_identity())
        user    = User.query.get(user_id)
        if not user.is_admin and "groups" not in get_user_modules(user):
            return redirect(url_for("dashboard"))
        groups  = Group.query.order_by(Group.created_at.desc()).all()
        reports = Report.query.filter_by(active=True).order_by(Report.name).all()
        group_report_ids = {}
        for g in groups:
            group_report_ids[g.id] = [
                rg.report_id for rg in ReportGroup.query.filter_by(group_id=g.id).all()
            ]
        return render_template("admin_groups.html",
                               user=user, groups=groups,
                               reports=reports, group_report_ids=group_report_ids)

    @app.route("/admin/groups/create", methods=["POST"])
    @jwt_required()
    def admin_create_group():
        user_id = int(get_jwt_identity())
        admin   = User.query.get(user_id)
        if not check_module_access(admin, "groups"):
            return jsonify({"error": "Sem permissão"}), 403
        data  = request.form
        group = Group(name=data["name"], description=data.get("description", ""), active=True)
        db.session.add(group)
        db.session.flush()
        for rid in request.form.getlist("report_ids"):
            db.session.add(ReportGroup(group_id=group.id, report_id=int(rid)))
        db.session.commit()
        return redirect(url_for("admin_groups"))

    @app.route("/admin/groups/edit/<int:group_id>", methods=["POST"])
    @jwt_required()
    def admin_edit_group(group_id):
        user_id = int(get_jwt_identity())
        admin   = User.query.get(user_id)
        if not check_module_access(admin, "groups"):
            return jsonify({"error": "Sem permissão"}), 403
        group             = Group.query.get_or_404(group_id)
        data              = request.form
        group.name        = data["name"]
        group.description = data.get("description", "")
        ReportGroup.query.filter_by(group_id=group_id).delete()
        for rid in request.form.getlist("report_ids"):
            db.session.add(ReportGroup(group_id=group_id, report_id=int(rid)))
        db.session.commit()
        return redirect(url_for("admin_groups"))

    @app.route("/admin/groups/toggle/<int:group_id>", methods=["POST"])
    @jwt_required()
    def admin_toggle_group(group_id):
        user_id = int(get_jwt_identity())
        admin   = User.query.get(user_id)
        if not check_module_access(admin, "groups"):
            return jsonify({"error": "Sem permissão"}), 403
        group        = Group.query.get_or_404(group_id)
        group.active = not group.active
        db.session.commit()
        return redirect(url_for("admin_groups"))

    @app.route("/admin/groups/delete/<int:group_id>", methods=["POST"])
    @jwt_required()
    def admin_delete_group(group_id):
        user_id = int(get_jwt_identity())
        admin   = User.query.get(user_id)
        if not check_module_access(admin, "groups"):
            return jsonify({"error": "Sem permissão"}), 403
        ReportGroup.query.filter_by(group_id=group_id).delete()
        Permission.query.filter_by(group_id=group_id).delete()
        RolePermission.query.filter_by(group_id=group_id).delete()
        Group.query.filter_by(id=group_id).delete()
        db.session.commit()
        return redirect(url_for("admin_groups"))

    # ── Admin Permissions ─────────────────────────────────────────

    @app.route("/admin/permissions")
    @jwt_required()
    def admin_permissions():
        user_id = int(get_jwt_identity())
        user    = User.query.get(user_id)
        if not user.is_admin and "permissions" not in get_user_modules(user):
            return redirect(url_for("dashboard"))
        users = User.query.filter_by(is_admin=False, active=True).order_by(User.name).all()
        return render_template("admin_permissions.html", user=user, users=users)
    
    @app.route("/admin/permissions/toggle", methods=["POST"])
    @jwt_required()
    def toggle_permission():
        user_id = int(get_jwt_identity())
        admin   = User.query.get(user_id)
        if not check_module_access(admin, "permissions"):
            return jsonify({"error": "Sem permissão"}), 403
        data       = request.json
        target_uid = data["user_id"]
        group_id   = data.get("group_id")
        report_id  = data.get("report_id")
        if group_id:
            perm = Permission.query.filter_by(
                user_id=target_uid, group_id=group_id, report_id=None).first()
        else:
            perm = Permission.query.filter_by(
                user_id=target_uid, report_id=report_id, group_id=None).first()
        if perm:
            db.session.delete(perm)
            db.session.commit()
            return jsonify({"status": "removed"})
        new_perm = Permission(
            user_id   = target_uid,
            group_id  = group_id  if group_id  else None,
            report_id = report_id if report_id else None
        )
        db.session.add(new_perm)
        db.session.commit()
        return jsonify({"status": "added"})

    # ── Admin RBAC ────────────────────────────────────────────────

    @app.route("/admin/roles")
    @jwt_required()
    def admin_roles():
        user_id = int(get_jwt_identity())
        user    = User.query.get(user_id)
        if not check_module_access(user, "roles"):
            return redirect(url_for("dashboard"))
        return render_template("admin_roles.html", user=user)
    
    @app.route("/admin/roles/manage")
    @jwt_required()
    def admin_roles_manage():
        user_id = int(get_jwt_identity())
        user    = User.query.get(user_id)
        if not check_module_access(user, "roles"):
            return redirect(url_for("dashboard"))
        roles = Role.query.order_by(Role.created_at.desc()).all()
        return render_template("admin_roles_manage.html", user=user, roles=roles)

    @app.route("/admin/roles/manage/create", methods=["POST"])
    @jwt_required()
    def admin_roles_manage_create():
        user_id = int(get_jwt_identity())
        admin   = User.query.get(user_id)
        if not check_module_access(admin, "roles"):
            return jsonify({"error": "Sem permissão"}), 403

        data = request.form
        key  = data["key"].lower().strip().replace(" ", "_")

        if Role.query.filter_by(key=key).first():
            roles = Role.query.order_by(Role.created_at.desc()).all()
            return render_template("admin_roles_manage.html",
                                   user=admin, roles=roles,
                                   error=f"A chave '{key}' já existe.")

        # Paleta de cores para novos perfis
        PALETTE = [
            '#0F6E56', '#1E40AF', '#92400E', '#5B21B6',
            '#065F46', '#9D174D', '#1E3A5F', '#713F12',
            '#166534', '#7C3AED', '#0369A1', '#B45309',
        ]
        used_colors = {r.color for r in Role.query.all()}
        available   = [c for c in PALETTE if c not in used_colors]
        color       = available[0] if available else PALETTE[len(Role.query.all()) % len(PALETTE)]

        role = Role(
            key         = key,
            label       = data["label"],
            description = data.get("description", ""),
            color       = color,
            active      = True
        )
        db.session.add(role)
        db.session.commit()
        return redirect(url_for("admin_roles_manage"))

    @app.route("/admin/roles/manage/edit/<int:role_id>", methods=["POST"])
    @jwt_required()
    def admin_roles_manage_edit(role_id):
        user_id = int(get_jwt_identity())
        admin   = User.query.get(user_id)
        if not check_module_access(admin, "roles"):
            return jsonify({"error": "Sem permissão"}), 403
        role             = Role.query.get_or_404(role_id)
        data             = request.form
        role.label       = data["label"]
        role.description = data.get("description", "")
        role.color       = data.get("color", role.color)
        role.active      = data.get("active") == "on"
        db.session.commit()
        return redirect(url_for("admin_roles_manage"))

    @app.route("/admin/roles/manage/delete/<int:role_id>", methods=["POST"])
    @jwt_required()
    def admin_roles_manage_delete(role_id):
        user_id = int(get_jwt_identity())
        admin   = User.query.get(user_id)
        if not check_module_access(admin, "roles"):
            return jsonify({"error": "Sem permissão"}), 403
        role = Role.query.get_or_404(role_id)
        # Verifica se tem usuários com essa role
        count = User.query.filter_by(role=role.key).count()
        if count > 0:
            roles = Role.query.order_by(Role.created_at.desc()).all()
            return render_template("admin_roles_manage.html",
                                   user=admin, roles=roles,
                                   error=f"Não é possível excluir: {count} usuário(s) usam este perfil.")
        RolePermission.query.filter_by(role=role.key).delete()
        RoleModulePermission.query.filter_by(role=role.key).delete()
        db.session.delete(role)
        db.session.commit()
        return redirect(url_for("admin_roles_manage"))

    @app.route("/admin/roles/toggle", methods=["POST"])
    @jwt_required()
    def toggle_role_permission():
        user_id = int(get_jwt_identity())
        admin   = User.query.get(user_id)
        if not check_module_access(admin, "roles"):
            return jsonify({"error": "Sem permissão"}), 403
        data      = request.json
        role      = data["role"]
        group_id  = data.get("group_id")
        report_id = data.get("report_id")
        if group_id:
            perm = RolePermission.query.filter_by(
                role=role, group_id=group_id, report_id=None).first()
        else:
            perm = RolePermission.query.filter_by(
                role=role, report_id=report_id, group_id=None).first()
        if perm:
            db.session.delete(perm)
            db.session.commit()
            return jsonify({"status": "removed"})
        new_perm = RolePermission(
            role      = role,
            group_id  = group_id  if group_id  else None,
            report_id = report_id if report_id else None
        )
        db.session.add(new_perm)
        db.session.commit()
        return jsonify({"status": "added"})

    # ── Admin Logs ────────────────────────────────────────────────

    @app.route("/admin/logs")
    @jwt_required()
    def admin_logs():
        user_id = int(get_jwt_identity())
        user    = User.query.get(user_id)
        if not check_module_access(user, "logs"):
            return redirect(url_for("dashboard"))

        from datetime import datetime, timedelta

        f_q       = request.args.get("q",         "").strip()
        f_user    = request.args.get("user_id",   "").strip()
        f_role    = request.args.get("role",       "").strip()
        f_report  = request.args.get("report_id", "").strip()
        f_date_from = request.args.get("date_from","").strip()
        f_date_to   = request.args.get("date_to",  "").strip()

        query = db.session.query(AccessLog, User, Report)\
            .join(User,   AccessLog.user_id   == User.id)\
            .join(Report, AccessLog.report_id == Report.id)

        if f_user:
            query = query.filter(AccessLog.user_id == int(f_user))
        if f_role:
            query = query.filter(User.role == f_role)
        if f_report:
            query = query.filter(AccessLog.report_id == int(f_report))
        if f_q:
            query = query.filter(
                db.or_(
                    User.name.ilike(f"%{f_q}%"),
                    Report.name.ilike(f"%{f_q}%")
                )
            )
        if f_date_from:
            try:
                query = query.filter(
                    AccessLog.accessed_at >= datetime.strptime(f_date_from, "%Y-%m-%d")
                )
            except Exception:
                pass
        if f_date_to:
            try:
                dt_to = datetime.strptime(f_date_to, "%Y-%m-%d") + timedelta(days=1)
                query = query.filter(AccessLog.accessed_at < dt_to)
            except Exception:
                pass

        logs = query.order_by(AccessLog.accessed_at.desc()).limit(500).all()

        all_users   = User.query.filter_by(active=True).order_by(User.name).all()
        all_reports = Report.query.filter_by(active=True).order_by(Report.name).all()
        all_roles   = Role.query.filter_by(active=True).order_by(Role.label).all()

        return render_template("admin_logs.html",
            user=user, logs=logs,
            all_users=all_users,
            all_reports=all_reports,
            all_roles=all_roles,
            f_q=f_q, f_user=f_user,
            f_role=f_role, f_report=f_report,
            f_date_from=f_date_from, f_date_to=f_date_to,
        )
    
    # ── Recuperação de senha ──────────────────────────────────────

    def gerar_codigo():
        return ''.join(random.choices(string.digits, k=6))

    @app.route("/forgot-password", methods=["GET", "POST"])
    def forgot_password():
        if request.method == "GET":
            return render_template("forgot_password.html")
        email = request.form.get("email", "").strip()
        user  = User.query.filter_by(email=email, active=True).first()
        if not user:
            return render_template("forgot_password.html",
                                   error="Este email não está cadastrado no sistema.")
        PasswordResetCode.query.filter_by(user_id=user.id, used=False).update({"used": True})
        db.session.flush()
        code       = gerar_codigo()
        expires_at = datetime.utcnow() + timedelta(minutes=15)
        reset      = PasswordResetCode(user_id=user.id, code=code, expires_at=expires_at)
        db.session.add(reset)
        db.session.commit()
        try:
            msg      = Message(subject="Código de recuperação de senha — Portal BI",
                               recipients=[user.email])
            msg.html = f"""
            <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
                        max-width:480px;margin:0 auto;padding:32px 24px;background:#fff">
              <h2 style="color:#1a1a2e;font-size:20px;margin-bottom:8px">Recuperação de senha</h2>
              <p style="color:#666;font-size:14px;margin-bottom:24px">
                Use o código abaixo para redefinir sua senha no Portal BI.
              </p>
              <div style="background:#f0f2f5;border-radius:12px;padding:24px;text-align:center;margin-bottom:24px">
                <span style="font-size:36px;font-weight:700;letter-spacing:8px;color:#4f46e5">{code}</span>
              </div>
              <p style="color:#888;font-size:13px">⏱ Expira em <strong>15 minutos</strong>.</p>
              <hr style="border:none;border-top:1px solid #eee;margin:24px 0">
              <p style="color:#bbb;font-size:12px">Portal BI</p>
            </div>"""
            mail.send(msg)
        except Exception as e:
            print(f"Erro ao enviar email: {e}")
        return redirect(url_for("reset_password", email=email))

    @app.route("/reset-password", methods=["GET", "POST"])
    def reset_password():
        if request.method == "GET":
            return render_template("reset_password.html", email=request.args.get("email", ""))
        email    = request.form.get("email", "").strip()
        code     = request.form.get("code", "").strip()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm", "")
        user     = User.query.filter_by(email=email, active=True).first()
        if not user:
            return render_template("reset_password.html", email=email,
                                   error="Email não encontrado.")
        if password != confirm:
            return render_template("reset_password.html", email=email,
                                   error="As senhas não coincidem.")
        if len(password) < 8:
            return render_template("reset_password.html", email=email,
                                   error="Mínimo 8 caracteres.")
        reset = PasswordResetCode.query.filter_by(
            user_id=user.id, code=code, used=False
        ).order_by(PasswordResetCode.created_at.desc()).first()
        if not reset:
            return render_template("reset_password.html", email=email,
                                   error="Código inválido ou já utilizado.")
        if datetime.utcnow() > reset.expires_at:
            reset.used = True
            db.session.commit()
            return render_template("reset_password.html", email=email,
                                   error="Código expirado. Solicite um novo.")
        user.password_hash = hash_password(password)
        reset.used         = True
        db.session.commit()
        return render_template("reset_password.html", success=True)
    
    # ── API Módulos ───────────────────────────────────────────────

    MODULES_LIST = [
        {"key": "logs",        "label": "Logs de acesso",  "icon": "📋"},
        {"key": "users",       "label": "Usuários",         "icon": "👥"},
        {"key": "groups",      "label": "Grupos",           "icon": "📁"},
        {"key": "reports",     "label": "Relatórios",       "icon": "📊"},
        {"key": "permissions", "label": "Permissões",       "icon": "🔑"},
        {"key": "roles",       "label": "Perfis RBAC",      "icon": "🎭"},
        {"key": "settings",    "label": "Configurações",    "icon": "⚙️"},
    ]

    @app.route("/admin/permissions/role/<string:role>")
    @jwt_required()
    def get_role_permissions(role):
        user_id = int(get_jwt_identity())
        admin   = User.query.get(user_id)
        if not admin.is_admin:
            return jsonify({"error": "Sem permissão"}), 403

        role_group_ids  = {rp.group_id  for rp in RolePermission.query.filter_by(role=role, report_id=None).all() if rp.group_id}
        role_report_ids = {rp.report_id for rp in RolePermission.query.filter_by(role=role, group_id=None).all() if rp.report_id}
        role_mod_keys   = {rm.module    for rm in RoleModulePermission.query.filter_by(role=role).all()}

        groups  = Group.query.filter_by(active=True).order_by(Group.name).all()
        reports = Report.query.filter_by(active=True).order_by(Report.name).all()

        role_obj   = Role.query.filter_by(key=role).first()
        user_count = User.query.filter_by(role=role, active=True).count()

        return jsonify({
            "role":       role,
            "label":      role_obj.label if role_obj else role,
            "user_count": user_count,
            "groups":     [{"id": g.id, "name": g.name, "active": g.id in role_group_ids} for g in groups],
            "reports":    [{"id": r.id, "name": r.name, "active": r.id in role_report_ids} for r in reports],
            "modules":    [{"key": m["key"], "label": m["label"], "icon": m["icon"], "active": m["key"] in role_mod_keys} for m in MODULES_LIST],
        })

    @app.route("/admin/roles/toggle-module", methods=["POST"])
    @jwt_required()
    def toggle_role_module():
        user_id = int(get_jwt_identity())
        admin   = User.query.get(user_id)
        if not check_module_access(admin, "roles"):
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

    @app.route("/admin/permissions/user/<int:target_id>")
    @jwt_required()
    def get_user_permissions(target_id):
        user_id = int(get_jwt_identity())
        admin   = User.query.get(user_id)
        if not check_module_access(admin, "permissions"):
            return jsonify({"error": "Sem permissão"}), 403

        target = User.query.get_or_404(target_id)

        ind_group_ids  = {p.group_id  for p in Permission.query.filter_by(user_id=target_id, report_id=None).all() if p.group_id}
        ind_report_ids = {p.report_id for p in Permission.query.filter_by(user_id=target_id, group_id=None).all() if p.report_id}
        ind_mod_keys   = {um.module   for um in UserModulePermission.query.filter_by(user_id=target_id).all()}

        role_group_ids  = {rp.group_id  for rp in RolePermission.query.filter_by(role=target.role, report_id=None).all() if rp.group_id}
        role_report_ids = {rp.report_id for rp in RolePermission.query.filter_by(role=target.role, group_id=None).all() if rp.report_id}
        role_mod_keys   = {rm.module    for rm in RoleModulePermission.query.filter_by(role=target.role).all()}

        groups  = Group.query.filter_by(active=True).order_by(Group.name).all()
        reports = Report.query.filter_by(active=True).order_by(Report.name).all()

        groups_data = []
        for g in groups:
            source = "role" if g.id in role_group_ids else ("individual" if g.id in ind_group_ids else None)
            groups_data.append({"id": g.id, "name": g.name, "source": source})

        reports_data = []
        for r in reports:
            source = "role" if r.id in role_report_ids else ("individual" if r.id in ind_report_ids else None)
            reports_data.append({"id": r.id, "name": r.name, "source": source})

        modules_data = []
        for m in MODULES_LIST:
            source = "role" if m["key"] in role_mod_keys else ("individual" if m["key"] in ind_mod_keys else None)
            modules_data.append({"key": m["key"], "label": m["label"], "icon": m["icon"], "source": source})

        return jsonify({
            "user": {
                "id":              target.id,
                "name":            target.name,
                "role":            target.role,
                "empresa_revenda": target.empresa_revenda or "—",
                "departamento":    target.departamento or "—",
                "ind_count":       len(ind_group_ids) + len(ind_report_ids) + len(ind_mod_keys)
            },
            "groups":  groups_data,
            "reports": reports_data,
            "modules": modules_data,
        })

    @app.route("/admin/permissions/toggle-module", methods=["POST"])
    @jwt_required()
    def toggle_user_module():
        user_id = int(get_jwt_identity())
        admin   = User.query.get(user_id)
        if not check_module_access(admin, "permissions"):
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
    
    # ── Configurações do Portal ───────────────────────────────────

    @app.route("/admin/settings", methods=["GET", "POST"])
    @jwt_required()
    def admin_settings():
        user_id = int(get_jwt_identity())
        user    = User.query.get(user_id)
        if not check_module_access(user, "settings"):
            return redirect(url_for("dashboard"))

        if request.method == "POST":
            data = request.form
            keys = ["company_name", "company_logo", "accent_color", "portal_name", "white_label"]
            for key in keys:
                setting = PortalSettings.query.filter_by(key=key).first()
                if setting:
                    setting.value      = data.get(key, "")
                    setting.updated_at = datetime.utcnow()
                else:
                    db.session.add(PortalSettings(key=key, value=data.get(key, "")))
            db.session.commit()
            return redirect(url_for("admin_settings"))

        settings = {s.key: s.value for s in PortalSettings.query.all()}
        return render_template("admin_settings.html", user=user, settings=settings)
    
    # ── Favoritos ─────────────────────────────────────────────────

    @app.route("/favorites/toggle/<int:report_id>", methods=["POST"])
    @jwt_required()
    def toggle_favorite(report_id):
        user_id = int(get_jwt_identity())
        fav = UserFavorite.query.filter_by(
            user_id=user_id, report_id=report_id
        ).first()
        if fav:
            db.session.delete(fav)
            db.session.commit()
            return jsonify({"status": "removed"})
        # Nova posição = último da lista
        max_pos = db.session.query(db.func.max(UserFavorite.position))\
            .filter_by(user_id=user_id).scalar() or 0
        new_fav = UserFavorite(
            user_id=user_id, report_id=report_id, position=max_pos + 1
        )
        db.session.add(new_fav)
        db.session.commit()
        return jsonify({"status": "added"})

    @app.route("/favorites/reorder", methods=["POST"])
    @jwt_required()
    def reorder_favorites():
        user_id = int(get_jwt_identity())
        data    = request.json
        ids     = data.get("ids", [])
        for i, rid in enumerate(ids):
            fav = UserFavorite.query.filter_by(
                user_id=user_id, report_id=rid
            ).first()
            if fav:
                fav.position = i
        db.session.commit()
        return jsonify({"status": "ok"})
    
    # ── Favoritos ─────────────────────────────────────────────────

    @app.route("/admin/analytics")
    @jwt_required()
    def admin_analytics():
        user_id = int(get_jwt_identity())
        user    = User.query.get(user_id)
        if not check_module_access(user, "logs"):
            return redirect(url_for("dashboard"))

        from sqlalchemy import func, cast, Date
        from datetime import datetime, timedelta

        # ── Filtros do topo ──────────────────────────────────────
        f_days    = int(request.args.get("days",    30))
        f_user    = request.args.get("user_id",  "").strip()
        f_role    = request.args.get("role",     "").strip()
        f_report  = request.args.get("report_id","").strip()

        # Limita opções de período
        if f_days not in [7, 15, 30, 60, 90]:
            f_days = 30

        hoje      = datetime.utcnow().date()
        data_ini  = hoje - timedelta(days=f_days)

        # Query base com filtros
        base_q = AccessLog.query.filter(AccessLog.accessed_at >= data_ini)
        if f_user:
            base_q = base_q.filter(AccessLog.user_id == int(f_user))
        if f_report:
            base_q = base_q.filter(AccessLog.report_id == int(f_report))
        if f_role:
            user_ids_role = [u.id for u in User.query.filter_by(role=f_role).all()]
            base_q = base_q.filter(AccessLog.user_id.in_(user_ids_role))

        # ── Cards de resumo ──────────────────────────────────────
        total_periodo = base_q.count()
        total_hoje    = AccessLog.query.filter(
            cast(AccessLog.accessed_at, Date) == hoje).count()
        total_semana  = AccessLog.query.filter(
            AccessLog.accessed_at >= hoje - timedelta(days=7)).count()
        usuarios_ativos = db.session.query(
            func.count(func.distinct(AccessLog.user_id))
        ).filter(AccessLog.accessed_at >= data_ini).scalar()

        # ── Acessos por dia ──────────────────────────────────────
        acessos_dia_raw = db.session.query(
            cast(AccessLog.accessed_at, Date).label('dia'),
            func.count().label('total')
        ).filter(AccessLog.accessed_at >= data_ini)
        if f_user:
            acessos_dia_raw = acessos_dia_raw.filter(AccessLog.user_id == int(f_user))
        if f_report:
            acessos_dia_raw = acessos_dia_raw.filter(AccessLog.report_id == int(f_report))
        if f_role:
            acessos_dia_raw = acessos_dia_raw.filter(AccessLog.user_id.in_(user_ids_role))
        acessos_dia_raw = acessos_dia_raw.group_by(
            cast(AccessLog.accessed_at, Date)
        ).order_by('dia').all()

        dias_map   = {str(r.dia): r.total for r in acessos_dia_raw}
        acessos_dia = []
        for i in range(f_days):
            d = str(data_ini + timedelta(days=i))
            acessos_dia.append({"dia": d, "total": dias_map.get(d, 0)})

        # ── Top relatórios ───────────────────────────────────────
        top_q = db.session.query(
            Report.id,
            Report.name,
            func.count(AccessLog.id).label('total')
        ).join(AccessLog, AccessLog.report_id == Report.id
        ).filter(AccessLog.accessed_at >= data_ini)
        if f_user:
            top_q = top_q.filter(AccessLog.user_id == int(f_user))
        if f_report:
            top_q = top_q.filter(AccessLog.report_id == int(f_report))
        if f_role:
            top_q = top_q.filter(AccessLog.user_id.in_(user_ids_role))
        top_reports = [
            {"id": r.id, "name": r.name, "total": r.total}
            for r in top_q.group_by(Report.id, Report.name
            ).order_by(func.count(AccessLog.id).desc()).limit(10).all()
        ]

        # ── Top usuários ─────────────────────────────────────────
        top_u_q = db.session.query(
            User.id,
            User.name,
            User.role,
            func.count(AccessLog.id).label('total')
        ).join(AccessLog, AccessLog.user_id == User.id
        ).filter(AccessLog.accessed_at >= data_ini)
        if f_user:
            top_u_q = top_u_q.filter(AccessLog.user_id == int(f_user))
        if f_report:
            top_u_q = top_u_q.filter(AccessLog.report_id == int(f_report))
        if f_role:
            top_u_q = top_u_q.filter(AccessLog.user_id.in_(user_ids_role))
        top_users = [
            {"id": u.id, "name": u.name, "role": u.role, "total": u.total}
            for u in top_u_q.group_by(User.id, User.name, User.role
            ).order_by(func.count(AccessLog.id).desc()).limit(10).all()
        ]

        # ── Acessos por hora ─────────────────────────────────────
        hora_q = db.session.query(
            func.extract('hour', AccessLog.accessed_at).label('hora'),
            func.count().label('total')
        ).filter(AccessLog.accessed_at >= data_ini)
        if f_user:
            hora_q = hora_q.filter(AccessLog.user_id == int(f_user))
        if f_report:
            hora_q = hora_q.filter(AccessLog.report_id == int(f_report))
        if f_role:
            hora_q = hora_q.filter(AccessLog.user_id.in_(user_ids_role))
        horas_map = {int(r.hora): r.total for r in hora_q.group_by('hora').all()}
        acessos_hora = [
            {"hora": f"{h:02d}h", "total": horas_map.get(h, 0)}
            for h in range(24)
        ]

        # ── Acessos por dia da semana ────────────────────────────
        sem_q = db.session.query(
            func.extract('dow', AccessLog.accessed_at).label('dow'),
            func.count().label('total')
        ).filter(AccessLog.accessed_at >= data_ini)
        if f_user:
            sem_q = sem_q.filter(AccessLog.user_id == int(f_user))
        if f_report:
            sem_q = sem_q.filter(AccessLog.report_id == int(f_report))
        if f_role:
            sem_q = sem_q.filter(AccessLog.user_id.in_(user_ids_role))
        dow_map = {int(r.dow): r.total for r in sem_q.group_by('dow').all()}
        dias_semana_names = ['Segunda','Terça','Quarta','Quinta','Sexta','Sábado','Domingo']
        acessos_semana = []
        for i, nome in enumerate(dias_semana_names):
            pg_dow = (i + 1) % 7
            acessos_semana.append({"dia": nome, "total": dow_map.get(pg_dow, 0)})

        # ── Acessos por perfil ───────────────────────────────────
        perf_q = db.session.query(
            User.role,
            func.count(AccessLog.id).label('total')
        ).join(AccessLog, AccessLog.user_id == User.id
        ).filter(AccessLog.accessed_at >= data_ini)
        if f_user:
            perf_q = perf_q.filter(AccessLog.user_id == int(f_user))
        if f_report:
            perf_q = perf_q.filter(AccessLog.report_id == int(f_report))
        if f_role:
            perf_q = perf_q.filter(AccessLog.user_id.in_(user_ids_role))
        roles_labels = {r.key: r.label for r in Role.query.all()}
        acessos_perfil = [
            {"role": roles_labels.get(r.role, r.role), "role_key": r.role, "total": r.total}
            for r in perf_q.group_by(User.role).all()
        ]

        # ── Dados para os selects de filtro ──────────────────────
        all_users   = User.query.filter_by(active=True).order_by(User.name).all()
        all_reports = Report.query.filter_by(active=True).order_by(Report.name).all()
        all_roles   = Role.query.filter_by(active=True).order_by(Role.label).all()

        return render_template("admin_analytics.html",
            user=user,
            total_hoje=total_hoje,
            total_semana=total_semana,
            total_periodo=total_periodo,
            usuarios_ativos=usuarios_ativos,
            acessos_dia=acessos_dia,
            top_reports=top_reports,
            top_users=top_users,
            acessos_hora=acessos_hora,
            acessos_semana=acessos_semana,
            acessos_perfil=acessos_perfil,
            all_users=all_users,
            all_reports=all_reports,
            all_roles=all_roles,
            f_days=f_days,
            f_user=f_user,
            f_role=f_role,
            f_report=f_report,
        )