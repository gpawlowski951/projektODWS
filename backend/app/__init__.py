from flask import Flask, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_argon2 import Argon2
from flask_pagedown import PageDown
db = SQLAlchemy()
limiter = Limiter(key_func=get_remote_address)
login_manager = LoginManager()
csrf = CSRFProtect()
argon2 = Argon2()
def create_app():
    app = Flask(__name__)
    app.config.from_object('app.config.Config')

    db.init_app(app)
    limiter.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    argon2.init_app(app)
    pagedown = PageDown(app)
    login_manager.login_view = 'auth.login'
    login_manager.session_protection = "strong"
    from .routes.auth import auth_bp
    from .routes.notes import notes_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(notes_bp)

    from .models import User
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    @app.template_filter('datetimeformat')
    def datetimeformat(value, format='%Y-%m-%d %H:%M'):
        return value.strftime(format)

    @app.template_filter('truncate')
    def truncate_filter(s, length=255):
        if len(s) <= length:
            return s
        return s[:length] + '...'

    @app.route('/index')
    def index():
        return redirect(url_for('notes.list_notes'))

    with app.app_context():
        from .models import User
        db.create_all()

    return app

