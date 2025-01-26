import base64
from io import BytesIO

import pyotp
import qrcode
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, current_user
from urllib.parse import urlsplit
from flask_limiter import util
from .. import limiter
from ..forms import LoginForm, RegistrationForm, TOTPVerificationForm
from ..models import User, db
import sqlalchemy as sa
import time
auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute", key_func=util.get_remote_address)
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm()
    if form.validate_on_submit():
        user = db.session.scalar(
            sa.select(User).where(User.username == form.username.data))
        if user is None or not user.verify_password(form.password.data):
            time.sleep(1)
            flash('Invalid username or password')
            return redirect(url_for('auth.login'))

        # Weryfikacja TOTP, jeśli sekret jest ustawiony
        if user.totp_secret:
            totp_code = form.totp_code.data
            if not user.verify_totp(totp_code):
                flash('Invalid TOTP code')
                return redirect(url_for('auth.login'))

        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or urlsplit(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', title='Sign In', form=form)


@auth_bp.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        new_user = User(
            username=form.username.data,
            email=form.email.data
        )
        new_user.set_password(form.password.data)
        new_user.set_totp_secret() # Generowanie sekretnego klucza TOTP
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please setup Two-Factor Authentication.', 'success')
        return redirect(url_for('auth.generate_totp', username=new_user.username)) # Przekierowanie do ustawiania TOTP
    return render_template('register.html', form=form)

@auth_bp.route('/generate_totp/<username>', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def generate_totp(username):
    user = db.session.scalar(sa.select(User).where(User.username == username))
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('auth.register'))

    totp_secret = user.totp_secret
    totp = pyotp.TOTP(totp_secret)
    provisioning_uri = totp.provisioning_uri(name=user.username, issuer_name="YourAppName") # Zmień "YourAppName" na nazwę Twojej aplikacji

    img = qrcode.make(provisioning_uri)
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    qr_code_base64 = base64.b64encode(buffered.getvalue()).decode("utf-8")

    form = TOTPVerificationForm()

    if form.validate_on_submit():
        verification_code = form.totp_code.data
        if user.verify_totp(verification_code):
            flash('TOTP setup verified successfully! You can now login.', 'success')
            return redirect(url_for('auth.login'))
        else:
            flash('Invalid verification code. Please try again.', 'danger')

    return render_template('generate_totp.html', username=username, qr_code=qr_code_base64, secret_key=totp_secret,
                           form=form)
@auth_bp.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))
