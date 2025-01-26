from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, BooleanField, SubmitField
from wtforms.fields.choices import SelectMultipleField
from wtforms.validators import DataRequired, Length, EqualTo, Optional
from .utils.validation import valusername, valuser_free, valemail, verpass_strength, valpass_match, veruser

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), veruser])
    password = PasswordField('Password', validators=[DataRequired()])
    totp_code = StringField('Two-Factor Code (TOTP)')
    remember_me = BooleanField('Zapamiętaj mnie')
    submit = SubmitField('Zaloguj')


class TwoFactorForm(FlaskForm):
  code = StringField('Kod', validators=[DataRequired()])
  submit = SubmitField('Potwierdź')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=20),
        valusername,
        valuser_free
    ])
    email = StringField('Email', validators=[DataRequired(), Length(max=100), valemail])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8),
        verpass_strength
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password'),
        valpass_match
    ])

class NoteForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content')
    public = BooleanField('Public')
    shared_with = SelectMultipleField('Share with users', coerce=int)
    encrypted = BooleanField('Encrypt Note')
    password = PasswordField('Password (for encryption/decryption)', validators=[Optional()]) # Password is optional for form validation but required when encrypting

class PasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])

class TOTPVerificationForm(FlaskForm):
    totp_code = StringField('Verification Code', validators=[DataRequired()])
    submit = SubmitField('Verify')