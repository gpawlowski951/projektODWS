import re
import bleach
from markdown import markdown
import math
from flask import current_app
from math import log2
import sqlalchemy as sqlal
from wtforms.validators import ValidationError, StopValidation

from flask_argon2 import check_password_hash

from app import db
from ..models import User


def validate_note_content(content):
    try:
        # Konwersja Markdown do HTML
        html_content = markdown(content)

        # Lista dozwolonych tagów i atrybutów
        allowed_tags = [
            'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
            'strong', 'em', 'a', 'img', 'p',
            'ul', 'ol', 'li', 'br', 'pre', 'code'
        ]

        allowed_attributes = {
            'a': ['href', 'title'],
            'img': ['src', 'alt', 'title']
        }

        # Sanityzacja HTML
        clean_html = bleach.clean(
            html_content,
            tags=allowed_tags,
            attributes=allowed_attributes,
            strip_comments=True,
            strip=True
        )

        # Walidacja długości
        max_length = current_app.config.get('MAX_NOTE_LENGTH', 100000)
        if len(clean_html) > max_length:
            return False

        # Sprawdź podstawową zawartość
        if not clean_html.strip():
            return False

        return clean_html

    except Exception as e:
        current_app.logger.error(f"Content validation error: {str(e)}")
        return False


def validate_share_request(data):
    """Walidacja żądania udostępnienia notatki"""
    if not isinstance(data, dict):
        return False

    # Honeypot dla botów
    if data.get('website') or data.get('_gotcha'):
        return False

    # Sprawdź czy podano prawidłowy typ udostępnienia
    public = data.get('public', False)
    users = data.get('users', [])

    if public and users:
        return False  # Nie można jednocześnie publicznie i prywatnie

    if not public and not users:
        return False  # Brak wybranego sposobu udostępnienia

    # Walidacja listy użytkowników
    if users:
        if not isinstance(users, list):
            return False

        if len(users) > current_app.config.get('MAX_SHARE_USERS', 10):
            return False

        username_re = re.compile(r'^[a-zA-Z0-9_\-.]{3,20}$')
        for user in users:
            if not username_re.match(user):
                return False

    # Dodatkowe zabezpieczenie CSRF
    if not data.get('csrf_token'):
        return False

    return True


def password_entropy(password):
    charset = 0

    if re.search(r'[a-z]', password): charset += 26
    if re.search(r'[A-Z]', password): charset += 26
    if re.search(r'\d', password): charset += 10
    if re.search(r'[^a-zA-Z0-9]', password): charset += 32

    if charset == 0:
        return 0

    entropy = len(password) * log2(charset)
    return round(entropy, 1)


def valusername(form, field):
    if not re.match(r'^[a-zA-Z0-9]+$', field.data):
        raise ValidationError('Nazwa użytkownika może zawierać tylko litery i cyfry')


def valuser_free(form, field):
    user = db.session.scalar(sqlal.select(User).where(User.username == field.data))

    if user is not None:
        raise ValidationError('Podana nazwa użytkownika jest już zajęta')


def valemail(form, field):
    email = db.session.scalar(sqlal.select(User).where(User.email == field.data))

    if email is not None:
        raise ValidationError('Podany adres e-mail jest już zajęty')


def valpass_match(form, field):
    if field.data != form.password.data:
        raise ValidationError('Hasła nie mogą się różnić')


def verpass_strength(form, field):
    if not re.match(
            r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!?@#$%^&*(){}\[\]_\-+=])[a-zA-Z\d!?@#$%^&*(){}\[\]_\-+=].{12,}$',
            field.data):
        raise ValidationError('Hasło nie spełnia wymogów')


def veruser(form, field):
    user = db.session.scalar(sqlal.select(User).where(User.username == field.data))

    if user is None:
        raise StopValidation('Nie ma takiego użytkownika')


def verpass(form, field):
    user = db.session.scalar(sqlal.select(User).where(User.username == form.username.data))
    hashed_password = user.password_hash

    password = form.password.data

    return check_password_hash(hashed_password, password)


def valinput(data, required_fields):
    if not isinstance(data, dict):
        return False
    return all(field in data for field in required_fields)
