from flask import Blueprint, request, render_template, redirect, url_for, make_response
from flask_jwt_extended import create_access_token, set_access_cookies, unset_jwt_cookies
from auth import hash_password, check_password, validate_password
from datetime import datetime, timedelta
from datetime import timezone
import random, string

BRASILIA = timezone(timedelta(hours=-3))
auth_bp  = Blueprint("auth", __name__)

@auth_bp.route("/")
def index():
    return redirect(url_for("auth.login"))

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    ctx     = auth_bp.ctx
    limiter = ctx["limiter"]

    @limiter.limit("10 per minute")
    def _login():
        if request.method == "GET":
            return render_template("login.html")
        data = request.form
        User = ctx["User"]
        user = User.query.filter_by(email=data["email"], active=True).first()
        if not user or not check_password(data["password"], user.password_hash):
            return render_template("login.html", error="Email ou senha incorretos.")
        token    = create_access_token(identity=str(user.id))
        response = make_response(redirect(url_for("dashboard.dashboard")))
        set_access_cookies(response, token)
        return response

    return _login()

@auth_bp.route("/logout")
def logout():
    response = make_response(redirect(url_for("auth.login")))
    unset_jwt_cookies(response)
    return response

@auth_bp.route("/setup", methods=["GET", "POST"])
def setup():
    ctx  = auth_bp.ctx
    db   = ctx["db"]
    User = ctx["User"]
    if User.query.count() > 0:
        return redirect(url_for("auth.login"))
    if request.method == "POST":
        data     = request.form
        password = data.get("password", "")
        valid, msg = validate_password(password)
        if not valid:
            return render_template("setup.html", error=msg)
        admin = User(
            name=data["name"], email=data["email"],
            password_hash=hash_password(password), is_admin=True
        )
        db.session.add(admin)
        db.session.commit()
        return redirect(url_for("auth.login"))
    return render_template("setup.html")

@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    ctx = auth_bp.ctx
    db  = ctx["db"]
    limiter = ctx["limiter"]

    @limiter.limit("5 per minute")
    def _forgot():
        from flask_mail import Message
        mail              = ctx["mail"]
        User              = ctx["User"]
        PasswordResetCode = ctx["PasswordResetCode"]

        if request.method == "GET":
            return render_template("forgot_password.html")
        email = request.form.get("email", "").strip()
        user  = User.query.filter_by(email=email, active=True).first()
        if not user:
            return render_template("forgot_password.html",
                                   error="Este email não está cadastrado no sistema.")
        PasswordResetCode.query.filter_by(user_id=user.id, used=False).update({"used": True})
        db.session.flush()
        code       = ''.join(random.choices(string.digits, k=6))
        expires_at = datetime.now(BRASILIA).replace(tzinfo=None) + timedelta(minutes=15)
        db.session.add(PasswordResetCode(user_id=user.id, code=code, expires_at=expires_at))
        db.session.commit()
        try:
            msg      = Message(subject="Código de recuperação — Portal BI", recipients=[user.email])
            msg.html = f"""
            <div style="font-family:-apple-system,sans-serif;max-width:480px;margin:0 auto;padding:32px;background:#fff">
              <h2 style="color:#1a1a2e">Recuperação de senha</h2>
              <div style="background:#f0f2f5;border-radius:12px;padding:24px;text-align:center;margin:24px 0">
                <span style="font-size:36px;font-weight:700;letter-spacing:8px;color:#4f46e5">{code}</span>
              </div>
              <p style="color:#888;font-size:13px">⏱ Expira em <strong>15 minutos</strong>.</p>
            </div>"""
            mail.send(msg)
        except Exception as e:
            print(f"Erro ao enviar email: {e}")
        return redirect(url_for("auth.reset_password", email=email))

    return _forgot()

@auth_bp.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    ctx = auth_bp.ctx
    db  = ctx["db"]
    limiter = ctx["limiter"]

    @limiter.limit("5 per minute")
    def _reset():
        User              = ctx["User"]
        PasswordResetCode = ctx["PasswordResetCode"]

        if request.method == "GET":
            return render_template("reset_password.html", email=request.args.get("email", ""))
        email    = request.form.get("email", "").strip()
        code     = request.form.get("code", "").strip()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm", "")
        user     = User.query.filter_by(email=email, active=True).first()
        if not user:
            return render_template("reset_password.html", email=email, error="Email não encontrado.")
        if password != confirm:
            return render_template("reset_password.html", email=email, error="As senhas não coincidem.")
        valid, msg = validate_password(password)
        if not valid:
            return render_template("reset_password.html", email=email, error=msg)
        reset = PasswordResetCode.query.filter_by(
            user_id=user.id, code=code, used=False
        ).order_by(PasswordResetCode.created_at.desc()).first()
        if not reset:
            return render_template("reset_password.html", email=email, error="Código inválido ou já utilizado.")
        if datetime.now(BRASILIA).replace(tzinfo=None) > reset.expires_at:
            reset.used = True
            db.session.commit()
            return render_template("reset_password.html", email=email, error="Código expirado. Solicite um novo.")
        user.password_hash = hash_password(password)
        reset.used         = True
        db.session.commit()
        return render_template("reset_password.html", success=True)

    return _reset()