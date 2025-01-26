from datetime import datetime

import pyotp
from flask_argon2 import generate_password_hash, check_password_hash
from . import db
from flask_login import UserMixin

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(320), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    totp_secret = db.Column(db.String(32))
    failed_logins = db.Column(db.Integer, default=0)
    last_login = db.Column(db.DateTime)
    notes = db.relationship('Note', backref='author', lazy=True)
    #signing_key = db.Column(db.String(128), nullable=False)
    def __repr__(self):
        return f'<User {self.username}>'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def set_totp_secret(self): # Metoda do generowania i ustawiania sekretnego klucza TOTP
        self.totp_secret = pyotp.random_base32()

    def verify_totp(self, totp_code): # Metoda do weryfikacji kodu TOTP
        if not self.totp_secret:
            return False # TOTP nie jest skonfigurowany
        totp = pyotp.TOTP(self.totp_secret)
        return totp.verify(totp_code)
note_sharing = db.Table('note_sharing', db.Column('user_id', db.Integer, db.ForeignKey('user.id')), db.Column('note_id', db.Integer, db.ForeignKey('note.id')))

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text)  # Plain text content - used if not encrypted
    content_encrypted = db.Column(db.Text)
    salt = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('user_notes', lazy=True))  # Zmieniono backref na 'user_notes'
    public = db.Column(db.Boolean, default=False)
    shared_with = db.relationship('User', secondary=note_sharing, backref=db.backref('shared_notes', lazy='dynamic'))
    encrypted = db.Column(db.Boolean, default=False)  #

    def __repr__(self):
        return f'<Note {self.id}: {self.title}>'


