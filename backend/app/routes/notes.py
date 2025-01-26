import base64
import os
from datetime import datetime

import bleach
import markdown
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import login_required, current_user
from sqlalchemy.exc import SQLAlchemyError
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from .. import limiter
from ..models import Note, db, note_sharing, User
from ..forms import NoteForm, PasswordForm

notes_bp = Blueprint('notes', __name__)
allowed_tags = ['p', 'strong', 'em', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'a', 'img', 'ul', 'ol', 'li']
allowed_attributes = {'a': ['href', 'title'], 'img': ['src', 'alt', 'title']}
def encrypt_content(content, password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    f = Fernet(key)
    token = f.encrypt(content.encode())
    return token.decode(), base64.b64encode(salt).decode()

def decrypt_content(encrypted_content, password, salt_b64):
    salt = base64.b64decode(salt_b64)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    f = Fernet(key)
    decrypted_content = f.decrypt(encrypted_content.encode()).decode()
    return decrypted_content

@notes_bp.route('/notes/new', methods=['GET', 'POST'])
@login_required
@limiter.limit("10/minute")
def new_note():
    form = NoteForm()
    form.shared_with.choices = [(user.id, user.username) for user in
                                User.query.filter(User.id != current_user.id).all()]
    if form.validate_on_submit():
        content = form.content.data
        encrypted = form.encrypted.data
        salt = None
        content_encrypted = None

        if encrypted:
            password = form.password.data
            if not password:
                flash('Password is required for encryption.', 'danger')
                return render_template('note_edit.html', form=form)
            content_encrypted, salt = encrypt_content(content, password)
            content = None # Clear plaintext content if encrypted

        note = Note(
            title=form.title.data,
            content=content,
            content_encrypted=content_encrypted,
            salt=salt,
            user_id=current_user.id,
            public=form.public.data,
            encrypted=encrypted
        )
        db.session.add(note)
        db.session.commit()
        selected_users = form.shared_with.data
        if selected_users:
            users_to_share_with = User.query.filter(User.id.in_(selected_users)).all()
            note.shared_with.extend(users_to_share_with)
            db.session.commit()
        flash('Note created successfully', 'success')
        return redirect(url_for('notes.list_notes'))
    return render_template('note_edit.html', form=form, action=url_for('notes.new_note'))

@notes_bp.route('/notes/<int:id>', methods=['GET', 'POST'])
@login_required
def view_note(id):
    note = Note.query.get_or_404(id)
    if note.user_id != current_user.id and not note.public and current_user not in note.shared_with:
        flash('Access denied', 'danger')
        return redirect(url_for('notes.list_notes'))

    password_form = PasswordForm()
    decrypted_content_html = None
    note_content_html = None

    if note.encrypted:
        if password_form.validate_on_submit():
            try:
                note_content = decrypt_content(note.content_encrypted, password_form.password.data, note.salt)
                note_content_html = markdown.markdown(note_content)
                decrypted_content_html = bleach.clean(
                    note_content_html,
                    tags=allowed_tags,
                    attributes=allowed_attributes)
            except Exception as e: # Catch decryption errors, wrong password etc.
                flash('Incorrect password or decryption error.', 'danger')
                current_app.logger.error(f"Decryption error: {str(e)}")
                return render_template('note_view.html', note=note, password_form=password_form, note_content_html=None)
        else:
             return render_template('note_view.html', note=note, password_form=password_form, note_content_html=None) # Render password form

    else:
        note_content_html = markdown.markdown(note.content)
        decrypted_content_html = bleach.clean(
            note_content_html,
            tags=allowed_tags,
            attributes=allowed_attributes)

    return render_template('note_view.html', note=note, note_content_html=decrypted_content_html, password_form=password_form if note.encrypted else None)


@notes_bp.route('/')
@notes_bp.route('/notes')
@login_required
def list_notes():
    page = request.args.get('page', 1, type=int)
    per_page = 10

    notes_query = Note.query.filter(
        (Note.user_id == current_user.id) |
        (Note.public == True) |
        (Note.shared_with.any(id=current_user.id))
    )

    notes = notes_query.order_by(Note.created_at.desc()).paginate(
        page=page,
        per_page=per_page,
        error_out=False
    )

    return render_template('notes.html', notes=notes)


@notes_bp.route('/notes/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_note(id):
    note = Note.query.get_or_404(id)

    if note.user_id != current_user.id:
        flash('You do not have permission to edit this note', 'danger')
        return redirect(url_for('notes.list_notes'))

    form = NoteForm(obj=note)
    form.shared_with.choices = [(user.id, user.username) for user in User.query.filter(User.id != current_user.id).all()]
    form.shared_with.data = [user.id for user in note.shared_with]

    if request.method == 'GET':
        if note.encrypted:
            form.content.data = "[Note is encrypted. Please view it to decrypt before editing.]" # Indicate encrypted status
            form.encrypted.data = True # Keep checkbox checked on edit
        else:
            form.content.data = note.content # Populate form with decrypted content if not encrypted
            form.encrypted.data = False


    if form.validate_on_submit():
        try:
            content = form.content.data
            encrypted_form = form.encrypted.data
            salt = note.salt # Keep existing salt if note was already encrypted
            content_encrypted = note.content_encrypted # Keep existing encrypted content

            if encrypted_form:
                password = form.password.data
                if not password and not note.encrypted: # Password required only if encrypting now or if it wasn't encrypted before
                    flash('Password is required for encryption.', 'danger')
                    return render_template('note_edit.html', form=form, note=note, action=url_for('notes.edit_note', id=note.id))

                if password: # Only re-encrypt if password provided or if note was previously encrypted and we want to re-encrypt on edit.
                    content_encrypted, salt = encrypt_content(content, password)
                    content = None # Clear plaintext content if encrypted
                elif note.encrypted:
                    content = None # Keep content as None if still encrypted and no new password provided for re-encryption

            else: # Not encrypted
                content_encrypted = None
                salt = None


            note.title = form.title.data
            note.content = content
            note.content_encrypted = content_encrypted
            note.salt = salt
            note.public = form.public.data
            note.encrypted = encrypted_form


            note.shared_with = []
            selected_users = form.shared_with.data
            if selected_users:
                users_to_share_with = User.query.filter(User.id.in_(selected_users)).all()
                note.shared_with.extend(users_to_share_with)

            note.updated_at = datetime.now()
            db.session.commit()

            flash('Note updated successfully', 'success')
            return redirect(url_for('notes.view_note', id=note.id))

        except SQLAlchemyError as e:
            db.session.rollback()
            flash('Error updating note', 'danger')
            current_app.logger.error(f"Note update error: {str(e)}")

    return render_template('note_edit.html',
                           form=form,
                           note=note,
                           action=url_for('notes.edit_note', id=note.id))

@notes_bp.route('/notes/delete/<int:id>', methods=['POST'])
@login_required
def delete_note(id):
    try:
        note = Note.query.get_or_404(id)

        if note.user_id != current_user.id:
            flash('You do not have permission to delete this note', 'danger')
            return redirect(url_for('notes.list_notes'))

        db.session.delete(note)
        db.session.commit()
        flash('Note deleted', 'success')
        return redirect(url_for('notes.list_notes'))

    except Exception as e:
        db.session.rollback()
        flash('Error occured during deleting the note', 'danger')
        return redirect(url_for('notes.list_notes'))
