from .auth             import auth_bp
from .dashboard        import dashboard_bp
from .admin_users      import admin_users_bp
from .admin_reports    import admin_reports_bp
from .admin_groups     import admin_groups_bp
from .admin_permissions import admin_permissions_bp
from .admin_roles      import admin_roles_bp
from .admin_logs       import admin_logs_bp
from .admin_settings   import admin_settings_bp

def init_routes(app, db, mail, limiter,
                User, Report, ReportRLS, Group, ReportGroup,
                Permission, RolePermission, AccessLog,
                PasswordResetCode, PortalSettings,
                RoleModulePermission, UserModulePermission,
                Role, UserFavorite):

    # Contexto compartilhado entre todos os blueprints
    ctx = dict(
        db=db, mail=mail, limiter=limiter,
        User=User, Report=Report, ReportRLS=ReportRLS,
        Group=Group, ReportGroup=ReportGroup,
        Permission=Permission, RolePermission=RolePermission,
        AccessLog=AccessLog, PasswordResetCode=PasswordResetCode,
        PortalSettings=PortalSettings,
        RoleModulePermission=RoleModulePermission,
        UserModulePermission=UserModulePermission,
        Role=Role, UserFavorite=UserFavorite,
    )

    # Registra cada blueprint com seu contexto
    auth_bp.ctx             = ctx
    dashboard_bp.ctx        = ctx
    admin_users_bp.ctx      = ctx
    admin_reports_bp.ctx    = ctx
    admin_groups_bp.ctx     = ctx
    admin_permissions_bp.ctx = ctx
    admin_roles_bp.ctx      = ctx
    admin_logs_bp.ctx       = ctx
    admin_settings_bp.ctx   = ctx

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(admin_users_bp)
    app.register_blueprint(admin_reports_bp)
    app.register_blueprint(admin_groups_bp)
    app.register_blueprint(admin_permissions_bp)
    app.register_blueprint(admin_roles_bp)
    app.register_blueprint(admin_logs_bp)
    app.register_blueprint(admin_settings_bp)