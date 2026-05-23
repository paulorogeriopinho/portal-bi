from flask import redirect, url_for, abort

def get_user_modules(ctx, user):
    RoleModulePermission = ctx["RoleModulePermission"]
    UserModulePermission = ctx["UserModulePermission"]
    if user.is_admin:
        from flask import current_app
        return {m["key"] for m in current_app.config["SYSTEM_MODULES"]}
    role_mods = {rm.module for rm in RoleModulePermission.query.filter_by(role=user.role).all()}
    user_mods = {um.module for um in UserModulePermission.query.filter_by(user_id=user.id).all()}
    return role_mods | user_mods

def check_module_access(ctx, user, module_key):
    if user.is_admin:
        return True
    if module_key == "settings":
        return False
    return module_key in get_user_modules(ctx, user)

def get_or_404(db, model, id):
    obj = db.session.get(model, id)
    if obj is None:
        abort(404)
    return obj

def get_user_reports(ctx, user):
    db           = ctx["db"]
    Group        = ctx["Group"]
    Report       = ctx["Report"]
    ReportGroup  = ctx["ReportGroup"]
    Permission   = ctx["Permission"]
    RolePermission = ctx["RolePermission"]
    UserFavorite = ctx["UserFavorite"]

    if user.is_admin:
        groups  = Group.query.filter_by(active=True).order_by(Group.name).all()
        all_rgs = ReportGroup.query.all()
    else:
        role_group_ids = {
            rp.group_id for rp in
            RolePermission.query.filter_by(role=user.role, report_id=None).all()
            if rp.group_id
        }
        user_group_ids = {
            p.group_id for p in
            Permission.query.filter_by(user_id=user.id, report_id=None).all()
            if p.group_id
        }
        all_group_ids = list(role_group_ids | user_group_ids)
        groups  = Group.query.filter(
            Group.id.in_(all_group_ids), Group.active == True
        ).order_by(Group.name).all() if all_group_ids else []
        all_rgs = ReportGroup.query.filter(
            ReportGroup.group_id.in_(all_group_ids)
        ).all() if all_group_ids else []

    group_report_map = {}
    for rg in all_rgs:
        group_report_map.setdefault(rg.group_id, []).append(rg.report_id)

    all_grouped_ids = {rg.report_id for rg in all_rgs}

    if user.is_admin:
        loose = Report.query.filter(
            Report.active == True,
            ~Report.id.in_(all_grouped_ids) if all_grouped_ids else Report.active == True
        ).all()
    else:
        role_report_ids = {
            rp.report_id for rp in
            RolePermission.query.filter_by(role=user.role, group_id=None).all()
            if rp.report_id
        }
        user_report_ids = {
            p.report_id for p in
            Permission.query.filter_by(user_id=user.id, group_id=None).all()
            if p.report_id
        }
        loose_ids = (role_report_ids | user_report_ids) - all_grouped_ids
        loose = Report.query.filter(
            Report.id.in_(loose_ids), Report.active == True
        ).all() if loose_ids else []

    favs    = UserFavorite.query.filter_by(user_id=user.id).order_by(UserFavorite.position).all()
    fav_ids = [f.report_id for f in favs]

    group_visible_ids = set(all_grouped_ids) if user.is_admin else {
        rid for gid in [g.id for g in groups]
        for rid in group_report_map.get(gid, [])
    }
    all_visible    = group_visible_ids | {r.id for r in loose}
    all_needed_ids = all_visible | set(fav_ids)

    reports_map = {
        r.id: r for r in
        Report.query.filter(Report.id.in_(all_needed_ids), Report.active == True).all()
    } if all_needed_ids else {}

    fav_reports = [
        reports_map[fid] for fid in fav_ids
        if fid in reports_map and (fid in all_visible or user.is_admin)
    ]

    groups_data = []
    for g in groups:
        rg_ids  = group_report_map.get(g.id, [])
        reports = [reports_map[rid] for rid in rg_ids if rid in reports_map]
        if reports:
            groups_data.append({"group": g, "reports": reports})

    return groups_data, loose, fav_reports, fav_ids

def can_access_report(ctx, user, report_id):
    Permission     = ctx["Permission"]
    RolePermission = ctx["RolePermission"]
    ReportGroup    = ctx["ReportGroup"]
    if user.is_admin:
        return True
    if Permission.query.filter_by(user_id=user.id, report_id=report_id, group_id=None).first():
        return True
    if RolePermission.query.filter_by(role=user.role, report_id=report_id, group_id=None).first():
        return True
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