from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, make_response, send_file, jsonify
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re
import os
import mimetypes
from werkzeug.utils import secure_filename
# Security Fix: Importing necessary hashing functions
from werkzeug.security import generate_password_hash, check_password_hash 
import psutil
import logging
from functools import wraps
import threading
import time
from datetime import datetime, timedelta
import io
import zipfile
import json
import subprocess

# --- Application Setup and Configuration ---
app = Flask(__name__)
# WARNING: In a real app, secret_key must be a strong, random value
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'default-dev-secret-password-should-be-stronger')

# Application-wide logging configuration
log_file = '/tmp/nas_app.log'
logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# MySQL database configuration - Reading from environment variables (BEST PRACTICE)
app.config['MYSQL_HOST'] = os.environ.get('MYSQL_HOST', 'localhost')
app.config['MYSQL_USER'] = os.environ.get('MYSQL_USER', 'nas_user')
# CRITICAL FIX: DO NOT hardcode production passwords.
app.config['MYSQL_PASSWORD'] = os.environ.get('MYSQL_PASSWORD', 'supersecretpassword')
app.config['MYSQL_DB'] = os.environ.get('MYSQL_DB', 'nas_web')

mysql = MySQL(app)

# Security and Quota Configuration
MAX_ATTEMPTS = 3
LOCKOUT_MINUTES = 2
MAX_FILE_SIZE = 10 * 1024 * 1024 # 10 MB limit for single file upload

# File upload configuration
UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', '/var/www/uploads/')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov', 'zip', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'}

# Services to monitor on the admin panel (assumes systemd)
MONITORED_SERVICES = [
    {"name": "mysql.service", "display_name": "Database (MySQL)"},
    {"name": "ssh", "display_name": "SSH Server"},
]

# --- Decorators and Helpers ---

def login_required(f):
    """Ensures user is logged in."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'loggedin' not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Protects routes that require admin privileges."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'loggedin' not in session or session.get('role') != 'admin':
            flash("You do not have permission to access this page.", "error")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    """Helper: check allowed extensions."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Helper: size conversion for Jinja filter
def human_readable_size(size):
    # size in bytes
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1_000:
            return f"{size:.1f} {unit}"
        size /= 1_000
    return f"{size:.1f} GB"

app.jinja_env.filters['human_size'] = human_readable_size

# Helper to create an alert from outside the main stats loop
def create_alert_helper(level, message):
    try:
        conn = mysql.connection
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT id FROM alerts WHERE message = %s AND is_read = 0", 
            (message,)
        )
        if cursor.fetchone():
            cursor.close()
            return
        
        cursor.execute(
            "INSERT INTO alerts (level, message) VALUES (%s, %s)",
            (level, message)
        )
        conn.commit()
        cursor.close()
        app.logger.info(f"Created alert: {level} - {message}")
    except Exception as e:
        app.logger.error(f"Error in create_alert_helper: {e}")

def bytes_to_gb(bytes_val):
    if bytes_val is None:
        return 0
    gb = bytes_val / (1024**3); return round(gb, 2)

# --- FILE & FOLDER ROUTES ---

@app.route("/upload_file", methods=["POST"])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('No file part', "error")
        return redirect(request.url)
    
    file = request.files['file']
    
    if file.filename == '':
        flash('No selected file', "warning")
        return redirect(request.url)
    
    if not allowed_file(file.filename):
        flash('Invalid file type.', "error")
        return redirect(request.url)

    # Calculate file size before DB insertion/hashing
    file.seek(0, os.SEEK_END)
    new_file_size = file.tell()
    file.seek(0)
    
    if new_file_size > MAX_FILE_SIZE:
        flash(f"File is too large. Maximum allowed size is {MAX_FILE_SIZE // (1024*1024)} MB.", "error")
        return redirect(url_for('dashboard'))

    user_id = session['id']
    folder_id = request.form.get('folder_id')
    folder_id = int(folder_id) if str(folder_id).isdigit() else None

    # Quota Check
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT quota_gb FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    user_quota_bytes = (user['quota_gb'] or 20) * 1024**3
    cursor.execute("SELECT SUM(size) as total_usage FROM files WHERE user_id = %s", (user_id,))
    usage = cursor.fetchone()
    current_usage_bytes = usage['total_usage'] or 0
    
    if (current_usage_bytes + new_file_size) > user_quota_bytes:
        cursor.close()
        flash(f"Upload failed: This file ({round(new_file_size / (1024**2), 1)} MB) would exceed your {user['quota_gb']} GB storage limit.", "error")
        if folder_id:
            return redirect(url_for('dashboard', folder=folder_id))
        else:
            return redirect(url_for('dashboard'))
    # --- END QUOTA CHECK ---

    original_name = secure_filename(file.filename)
    mime_type = file.mimetype or mimetypes.guess_type(original_name)[0]
    size = new_file_size
    
    # Insert DB record first to get file ID
    cursor.execute("""
        INSERT INTO files (user_id, folder_id, original_name, mime_type, size)
        VALUES (%s, %s, %s, %s, %s)
    """, (user_id, folder_id, original_name, mime_type, size))
    mysql.connection.commit()
    file_id = cursor.lastrowid
    cursor.close()

    # Save file using its DB ID as filename
    ext = os.path.splitext(original_name)[1]
    storage_name = f"{file_id}{ext}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], storage_name)
    file.save(filepath)

    flash('File uploaded successfully.', "success")
    app.logger.info(f"User '{session['username']}' UPLOADED file '{original_name}' (ID: {file_id}).")
    
    if folder_id:
        return redirect(url_for('dashboard', folder=folder_id))
    else:
        return redirect(url_for('dashboard'))

@app.route("/create_folder", methods=["POST"])
@login_required
def create_folder():
    folder_name = request.form.get('folder_name')
    parent_id = request.form.get('parent_id')
    parent_id = int(parent_id) if str(parent_id).isdigit() else None

    if not folder_name or folder_name.strip() == '':
        flash("Folder name cannot be empty", "error")
        return redirect(url_for('dashboard'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("""
        INSERT INTO folders (user_id, name, parent_id)
        VALUES (%s, %s, %s)
    """, (session['id'], folder_name.strip(), parent_id))
    mysql.connection.commit()
    new_folder_id = cursor.lastrowid
    cursor.close()
    
    flash(f"Folder '{folder_name}' created successfully", "success")
    app.logger.info(f"User '{session['username']}' CREATED folder '{folder_name}' (ID: {new_folder_id}, Parent ID: {parent_id}).")

    if parent_id:
        return redirect(url_for('dashboard', folder=parent_id))
    else:
        return redirect(url_for('dashboard'))

@app.route("/rename_folder", methods=["POST"])
@login_required
def rename_folder():
    folder_name = request.form.get('folder_name')
    folder_id = request.form.get('folder_id')
    parent_id = request.form.get('parent_id')

    folder_id = int(folder_id) if str(folder_id).isdigit() else None
    parent_id = int(parent_id) if str(parent_id).isdigit() else None

    if not folder_id:
        flash("Folder ID can't be None", "error")
        return redirect(url_for('dashboard'))
    if not folder_name or folder_name.strip() == '':
        flash("Folder name cannot be empty", "error")
        return redirect(url_for('dashboard'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("""
                    UPDATE folders 
                    SET name = %s 
                    WHERE id = %s AND user_id = %s
    """, (folder_name.strip(), folder_id, session['id']))
    mysql.connection.commit()
    cursor.close()
    
    flash(f"Folder '{folder_name}' renamed successfully", "success")
    app.logger.info(f"User '{session['username']}' RENAMED folder ID {folder_id} to '{folder_name}'.")
    
    if parent_id:
        return redirect(url_for('dashboard', folder=parent_id))
    else:
        return redirect(url_for('dashboard'))

@app.route("/download_folder/<int:folder_id>", methods=["GET"])
@login_required
def download_folder(folder_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM folders WHERE id = %s AND user_id = %s", (folder_id, session['id']))
    folder_record = cursor.fetchone()
    if not folder_record:
        cursor.close()
        return "Folder not found or permission denied", 404
        
    app.logger.info(f"User '{session['username']}' STARTED DOWNLOAD of folder '{folder_record['name']}' (ID: {folder_id}).")

    memory_file = io.BytesIO()
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        # Re-use the cursor for recursive calls, ensuring connection is consistent
        add_folder_to_zip(cursor, zf, folder_id, session['id'], base_path="")
    memory_file.seek(0)
    cursor.close()
    
    return send_file(
        memory_file,
        as_attachment=True,
        download_name=f"{folder_record['name']}.zip",
        mimetype='application/zip'
    )

def add_folder_to_zip(cursor, zf, folder_id, user_id, base_path):
    # This helper uses the existing cursor passed from the main route
    cursor.execute("SELECT name FROM folders WHERE id = %s", (folder_id,))
    folder = cursor.fetchone()
    folder_name = folder['name'] if folder else f"folder_{folder_id}"
    current_path = os.path.join(base_path, folder_name)
    
    cursor.execute("SELECT id, original_name FROM files WHERE folder_id = %s AND user_id = %s", (folder_id, user_id))
    files = cursor.fetchall()
    for f in files:
        ext = os.path.splitext(f['original_name'])[1]
        storage_name = f"{f['id']}{ext}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], storage_name)
        if os.path.exists(filepath):
            zf.write(filepath, arcname=os.path.join(current_path, f['original_name']))

    cursor.execute("SELECT id FROM folders WHERE parent_id = %s AND user_id = %s", (folder_id, user_id))
    subfolders = cursor.fetchall()
    for sub in subfolders:
        add_folder_to_zip(cursor, zf, sub['id'], user_id, current_path)

@app.route("/delete_folder", methods=["POST"])
@login_required
def delete_folder():
    folder_id = request.form.get('folder_id')
    parent_id = request.form.get('parent_id')

    folder_id = int(folder_id) if str(folder_id).isdigit() else None
    parent_id = int(parent_id) if str(parent_id).isdigit() else None

    if not folder_id:
        flash("Folder ID can't be None", "error")
        return redirect(url_for('dashboard'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT id, name FROM folders WHERE id = %s AND user_id = %s", (folder_id, session['id']))
    folder_record = cursor.fetchone()
    if not folder_record:
        cursor.close()
        flash("Folder not found or permission denied", "error")
        return redirect(url_for('dashboard'))
    try:
        delete_folder_recursive(cursor, folder_id, session['id'])
        mysql.connection.commit()
        
        flash("Folder and its contents deleted successfully.", "success")
        app.logger.info(f"User '{session['username']}' DELETED folder '{folder_record['name']}' (ID: {folder_id}).")
        
    except Exception as e:
        mysql.connection.rollback()
        flash(f"Error deleting folder: {str(e)}", "error")
    
    cursor.close()
    if parent_id:
        return redirect(url_for('dashboard', folder=parent_id))
    else:
        return redirect(url_for('dashboard'))

def delete_folder_recursive(cursor, folder_id, user_id):
    # This helper uses the existing cursor passed from the main route
    cursor.execute("SELECT id FROM folders WHERE parent_id = %s AND user_id = %s", (folder_id, user_id))
    sub_folders = cursor.fetchall()
    for sub in sub_folders:
        delete_folder_recursive(cursor, sub['id'], user_id)

    # Fetch all files in this folder
    cursor.execute("SELECT id, original_name FROM files WHERE folder_id = %s AND user_id = %s", (folder_id, user_id))
    files = cursor.fetchall()

    for file_record in files:
        file_id = file_record['id']
        ext = os.path.splitext(file_record['original_name'])[1]
        storage_name = f"{file_id}{ext}"
        filepath = os.path.join(UPLOAD_FOLDER, storage_name)

        # Try to delete the file from disk
        try:
            if os.path.exists(filepath):
                os.remove(filepath)
        except Exception as e:
            app.logger.error(f"Error deleting physical file {filepath}: {e}")

    # Delete file records from the DB
    cursor.execute("DELETE FROM files WHERE folder_id = %s AND user_id = %s", (folder_id, user_id))

    # Delete the folder itself
    cursor.execute("DELETE FROM folders WHERE id = %s AND user_id = %s", (folder_id, user_id))

# FIX: Added "POST" back to methods list for robustness.
@app.route("/dashboard", methods=["GET", "POST"]) 
@login_required
def dashboard():
    folder_id = None
    folder_name = ""

    # Prioritize GET query param for navigation, ignore POST data for navigation
    folder_id = request.args.get('folder') 
    
    folder_id = int(folder_id) if str(folder_id).isdigit() else None
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    current_folder_id = folder_id
    parent_id = None

    if current_folder_id is not None:
        cursor.execute(
            "SELECT parent_id, name FROM folders WHERE id = %s AND user_id = %s",
            (current_folder_id, session['id'])
        )
        folder = cursor.fetchone()
        if folder:
            parent_id = folder['parent_id']
            folder_name = folder['name']
        else:
            flash("Folder not found.", "error")
            cursor.close()
            return redirect(url_for('dashboard'))
            
    # Fetch folders
    if current_folder_id is not None:
        cursor.execute(
            "SELECT * FROM folders WHERE user_id = %s AND parent_id = %s",
            (session['id'], current_folder_id)
        )
        folders = cursor.fetchall()
        cursor.execute(
            "SELECT * FROM files WHERE user_id = %s AND folder_id = %s",
            (session['id'], current_folder_id)
        )
        files = cursor.fetchall()
    else:
        cursor.execute(
            "SELECT * FROM folders WHERE user_id = %s AND parent_id IS NULL",
            (session['id'],)
        )
        folders = cursor.fetchall()
        cursor.execute(
            "SELECT * FROM files WHERE user_id = %s AND folder_id IS NULL",
            (session['id'],)
        )
        files = cursor.fetchall()

    # Get user quota/usage stats for the dashboard sidebar
    cursor.execute("SELECT quota_gb FROM users WHERE id = %s", (session['id'],))
    user = cursor.fetchone()
    user_quota_gb = user['quota_gb'] if user and user['quota_gb'] is not None else 20

    cursor.execute("SELECT SUM(size) as total_usage FROM files WHERE user_id = %s", (session['id'],))
    usage = cursor.fetchone()
    current_usage_bytes = usage['total_usage'] or 0
    current_usage_gb = round(current_usage_bytes / (1024**3), 2)
    
    user_quota_bytes = user_quota_gb * 1024**3
    usage_percent = 0
    if user_quota_bytes > 0:
        usage_percent = round((current_usage_bytes / user_quota_bytes) * 100, 1)
    
    cursor.close()

    response = make_response(render_template(
        "dashboard.html",
        username=session['username'],
        role=session['role'],
        folders=folders,
        files=files,
        current_folder_id=current_folder_id,
        parent_id=parent_id,
        folder_name=folder_name,
        current_usage_gb=current_usage_gb,
        user_quota_gb=user_quota_gb,
        usage_percent=usage_percent
    ))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, proxy-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route("/download_file/<int:file_id>", methods=["GET"])
@login_required
def download_file(file_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM files WHERE id = %s AND user_id = %s", (file_id, session['id']))
    file_record = cursor.fetchone()
    cursor.close()
    if not file_record:
        return "File not found or permission denied", 404
        
    app.logger.info(f"User '{session['username']}' STARTED DOWNLOAD of file '{file_record['original_name']}' (ID: {file_id}).")

    ext = os.path.splitext(file_record['original_name'])[1]
    storage_name = f"{file_id}{ext}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], storage_name)
    
    if not os.path.exists(filepath):
        return "File missing on server", 404
        
    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        storage_name,
        as_attachment=True,
        download_name=file_record['original_name'],
        mimetype=file_record['mime_type']
    )

@app.route("/delete_file", methods=["POST"])
@login_required
def delete_file():
    file_id = request.form.get('file_id')
    parent_id = request.form.get('parent_id')

    file_id = int(file_id) if str(file_id).isdigit() else None
    parent_id = int(parent_id) if str(parent_id).isdigit() else None

    if not file_id:
        flash("File ID can't be None", "error")
        return redirect(url_for('dashboard'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM files WHERE id = %s AND user_id = %s", (file_id, session['id']))
    file_record = cursor.fetchone()
    
    if not file_record:
        cursor.close()
        flash("File not found or permission denied", "error")
        return redirect(url_for('dashboard'))

    ext = os.path.splitext(file_record['original_name'])[1]
    storage_name = f"{file_id}{ext}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], storage_name)
    
    try:
        if os.path.exists(filepath):
            os.remove(filepath)
        cursor.execute("DELETE FROM files WHERE id = %s AND user_id = %s", (file_id, session['id']))
        mysql.connection.commit()
        
        flash("File deleted successfully.", "success")
        app.logger.info(f"User '{session['username']}' DELETED file '{file_record['original_name']}' (ID: {file_id}).")
        
    except Exception as e:
        mysql.connection.rollback()
        flash(f"Error deleting file: {str(e)}", "error")
        
    cursor.close()
    if parent_id:
        return redirect(url_for('dashboard', folder=parent_id))
    else:
        return redirect(url_for('dashboard'))


# --- USER AUTH ROUTES ---

@app.route("/")
def index():
    if 'loggedin' in session:
        return redirect(url_for('dashboard'))
    return render_template("index.html")

@app.route("/login")
def login():
    if 'loggedin' in session:
        return redirect(url_for('dashboard'))
    return render_template("login.html")

@app.route("/register")
def register():
    if 'loggedin' in session:
        return redirect(url_for('dashboard'))
    return render_template("register.html")

@app.route("/login_request", methods=["POST"])
def login_request():
    username = request.form.get("username")
    password = request.form.get("password")
    
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
    account = cursor.fetchone()
    now = datetime.now()

    if account:
        # --- START LOGIN ATTEMPT LOGIC ---
        cursor.execute('SELECT * FROM login_attempts WHERE user_id = %s', (account['id'],))
        attempt_record = cursor.fetchone()

        if not attempt_record:
            cursor.execute("INSERT INTO login_attempts (user_id) VALUES (%s)", (account['id'],))
            mysql.connection.commit()
            attempts = 0
            last_failed = None
        else:
            attempts = attempt_record['attempts']
            last_failed = attempt_record['last_failed']

        if last_failed and attempts >= MAX_ATTEMPTS:
            lockout_end = last_failed + timedelta(minutes=LOCKOUT_MINUTES)
            if now < lockout_end:
                remaining = int((lockout_end - now).total_seconds() // 60) + 1
                msg = f"Account locked. Try again in {remaining} minute(s)."
                flash(msg, "error")
                cursor.close() # <-- Safe to close here
                return redirect(url_for('login'))
        # --- END LOGIN ATTEMPT LOGIC ---

        if check_password_hash(account['password'], password):
            # Password IS correct
            cursor.execute("UPDATE login_attempts SET attempts = 0, last_failed = NULL WHERE user_id = %s", (account['id'],))
            mysql.connection.commit()
            cursor.close() # <-- Safe to close here

            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            session['role'] = account['role']
            app.logger.info(f"User '{username}' logged in successfully.")
            return redirect(url_for('dashboard'))
        else:
            # Password is NOT correct
            attempts += 1
            cursor.execute("UPDATE login_attempts SET attempts = %s, last_failed = %s WHERE user_id = %s", (attempts, now, account['id']))
            mysql.connection.commit()
            
            app.logger.warning(f"Failed login attempt for username: {username}")
            
            # --- THIS IS THE FIX ---
            # Call the helper BEFORE closing the cursor
            create_alert_helper('WARNING', f'Failed login attempt for username: {username}')
            
            if attempts >= MAX_ATTEMPTS:
                msg = f"Account locked due to too many failed attempts. Try again in {LOCKOUT_MINUTES} minutes."
            else:
                remaining = MAX_ATTEMPTS - attempts
                msg = f"Invalid username or password. {remaining} attempt(s) remaining."
            
            flash(msg, "error")
            cursor.close() # <-- Now it's safe to close
            return redirect(url_for('login'))

    else:
        # Account does not exist
        app.logger.warning(f"Failed login attempt for non-existent username: {username}")
        
        # --- THIS IS THE FIX ---
        # Call the helper BEFORE closing the cursor (and add it back)
        create_alert_helper('WARNING', f'Failed login attempt for username: {username}')
        
        flash("Invalid username or password.", "error")
        cursor.close() # <-- Now it's safe to close
        return redirect(url_for('login'))


@app.route("/register_request", methods=["POST"])
def register_request():
    username = request.form.get("username")
    password = request.form.get("password")
    
    if len(password) < 8:
        flash('Password must be at least 8 characters long!', "error")
        return redirect(url_for('register', _t=int(time.time())))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
    account = cursor.fetchone()
    
    if account:
        flash('Username already exists!', "error")
    elif not re.match(r'^[A-Za-z0-9]+$', username):
        flash('Username must contain only letters and numbers!', "error")
    else:
        # This is the only successful case
        hashed_password = generate_password_hash(password)
        # Default quota is 20 GB
        cursor.execute('INSERT INTO users (username, password, role, quota_gb) VALUES (%s, %s, %s, %s)', (username, hashed_password, 'user', 20))
        mysql.connection.commit()
        cursor.close()
        
        flash("Registration successful! Please log in.", "success")
        # This adds a timestamp to the URL (e.g., /register?_t=123456789) to "bust" the cache
        return redirect(url_for('register', _t=int(time.time()))) # <-- The only SUCCESS redirect
    
    # All error cases will fall through to here
    cursor.close()
    return redirect(url_for('register')) # <-- The new ERROR redirect

@app.route("/delete_account", methods=["POST"])
@login_required
def delete_account():
    user_id = session['id']
    username = session['username']
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        # Delete physical files first
        cursor.execute("SELECT id, original_name FROM files WHERE user_id = %s", (user_id,))
        all_files = cursor.fetchall()
        for file in all_files:
            ext = os.path.splitext(file['original_name'])[1]
            storage_name = f"{file['id']}{ext}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], storage_name)
            if os.path.exists(filepath):
                os.remove(filepath)
            
        # Delete user record (triggers CASCADE for files/folders metadata)
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        mysql.connection.commit()
        cursor.close()
        
        app.logger.info(f"User '{username}' DELETED OWN ACCOUNT (ID: {user_id}).")

        session.clear()
        flash("Your account and all associated data have been permanently deleted.")
        return redirect(url_for('login'))
    except Exception as e:
        mysql.connection.rollback()
        cursor.close()
        flash(f"Error deleting account: {e}", "error")
        return redirect(url_for('dashboard'))

@app.route("/delete_user", methods=["POST"])
@admin_required
def delete_user():
    user_id_to_delete = request.form.get('user_id')
    user_id_to_delete = int(user_id_to_delete) if str(user_id_to_delete).isdigit() else None

    if not user_id_to_delete or user_id_to_delete == session['id']:
        flash("Invalid request. You cannot delete your own admin account.", "error")
        return redirect(url_for('admin_monitoring_panel'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        cursor.execute("SELECT username FROM users WHERE id = %s", (user_id_to_delete,))
        user_record = cursor.fetchone()
        if not user_record:
            flash("User not found.", "error")
            cursor.close()
            return redirect(url_for('admin_monitoring_panel'))
            
        username_to_delete = user_record['username']
        
        # Manually delete physical files first
        cursor.execute("SELECT id, original_name FROM files WHERE user_id = %s", (user_id_to_delete,))
        all_files = cursor.fetchall()
        for file in all_files:
            ext = os.path.splitext(file['original_name'])[1]
            storage_name = f"{file['id']}{ext}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], storage_name)
            if os.path.exists(filepath):
                os.remove(filepath)

        # Delete user from DB (CASCADE cleans up files/folders metadata)
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id_to_delete,))
        mysql.connection.commit()
        
        app.logger.info(f"Admin '{session['username']}' DELETED user '{username_to_delete}' (ID: {user_id_to_delete}).")
        
        flash(f"User '{username_to_delete}' successfully deleted.", "success")
        
    except Exception as e:
        mysql.connection.rollback()
        app.logger.error(f"Error deleting user {user_id_to_delete}: {e}")
        flash(f"Error deleting user: {e}", "error")
        
    cursor.close()
    return redirect(url_for('admin_monitoring_panel'))

@app.route("/logout", methods=["POST"])
def logout():
    app.logger.info(f"User '{session.get('username', 'N/A')}' logged out.")
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

# --- Admin Panel & API Routes ---

@app.route("/admin_monitoring_panel")
@admin_required
def admin_monitoring_panel():
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        
        # Query for the storage report (This is correct)
        cursor.execute("""
            SELECT 
                users.id, 
                users.username, 
                users.role, 
                users.quota_gb,
                SUM(files.size) as total_usage
            FROM users
            LEFT JOIN files ON users.id = files.user_id
            GROUP BY users.id
            ORDER BY total_usage DESC
        """)
        users_raw = cursor.fetchall()
        cursor.close() 

        # --- THIS IS THE CORRECTED LOGIC ---
        users_report = []
        for user in users_raw:
            # Calculate usage/quota for EACH user in the loop
            usage_bytes = user['total_usage'] or 0
            quota_gb = user['quota_gb'] if user and user['quota_gb'] is not None else 20
            quota_bytes = quota_gb * 1024**3
            usage_gb = round(usage_bytes / (1024**3), 2)
            
            # Define percent
            percent = 0 
            if quota_bytes > 0:
                percent = round((usage_bytes / quota_bytes) * 100, 1)

            # This data is needed by your template
            users_report.append({
                "id": user['id'],
                "username": user['username'],
                "role": user['role'],
                "usage_gb": usage_gb, 
                "quota_gb": quota_gb,
                "percent": percent  # Now 'percent' is correctly defined
            })
        # --- END OF CORRECTED LOGIC ---
        
        return render_template("admin_monitoring_panel.html", users_report=users_report)

    except Exception as e:
        app.logger.error(f"Error in /admin_monitoring_panel: {e}")
        flash(f"Error generating admin panel: {e}", "error")
        return redirect(url_for('dashboard'))
@app.route("/update_quota", methods=["POST"])
@admin_required
def update_quota():
    try:
        user_id = request.form.get('user_id')
        new_quota = request.form.get('new_quota')

        if not user_id or not new_quota:
            flash("Missing user ID or quota value.", "error")
            return redirect(url_for('admin_monitoring_panel'))

        cursor = mysql.connection.cursor()
        cursor.execute("UPDATE users SET quota_gb = %s WHERE id = %s", (int(new_quota), int(user_id)))
        mysql.connection.commit()
        cursor.close()
        
        flash(f"User ID {user_id}'s quota updated to {new_quota} GB.", "success")
        app.logger.info(f"Admin '{session['username']}' updated quota for user ID {user_id} to {new_quota} GB.")

    except Exception as e:
        mysql.connection.rollback()
        app.logger.error(f"Error in /update_quota: {e}")
        flash(f"Error updating quota: {e}", "error")
    
    return redirect(url_for('admin_monitoring_panel'))

# --- API Endpoints ---
# (APIs remain mostly unchanged from the enhanced snippet, ensuring separation of concerns)

@app.route("/api/stats_history")
@admin_required
def api_stats_history():
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("""
            SELECT timestamp, cpu_percent, mem_percent, net_sent_mbps, net_recv_mbps,
                   disk_read_mbps, disk_write_mbps
            FROM system_stats 
            WHERE timestamp > (NOW() - INTERVAL 1 HOUR)
            ORDER BY timestamp ASC
        """)
        stats = cursor.fetchall()
        cursor.close()
        formatted_data = {
            "labels": [s['timestamp'].strftime('%Y-%m-%dT%H:%M:%S') for s in stats],
            "cpu": [s['cpu_percent'] for s in stats],
            "mem": [s['mem_percent'] for s in stats],
            "net_sent": [s['net_sent_mbps'] or 0 for s in stats],
            "net_recv": [s['net_recv_mbps'] or 0 for s in stats],
            "disk_read": [s['disk_read_mbps'] or 0 for s in stats],
            "disk_write": [s['disk_write_mbps'] or 0 for s in stats]
        }
        return jsonify(formatted_data)
    except Exception as e:
        app.logger.error(f"Error in /api/stats_history: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/stats_snapshot")
@admin_required 
def api_stats_snapshot():
    try:
        disk = psutil.disk_usage('/') 
        stats = {
            "cpu_percent": psutil.cpu_percent(interval=None),
            "mem_percent": psutil.virtual_memory().percent,
            "disk_percent": disk.percent,
            "disk_used_gb": bytes_to_gb(disk.used),
            "disk_total_gb": bytes_to_gb(disk.total)
        }
        return jsonify(stats)
    except Exception as e:
        app.logger.error(f"Error in /api/stats_snapshot: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/logs")
@admin_required
def api_logs():
    log_file_path = '/tmp/nas_app.log'
    logs = []
    try:
        if not os.path.exists(log_file_path):
            return jsonify({"logs": [{"timestamp": "N/A", "level": "INFO", "message": "Log file not found. It will be created on first log."}]})
        
        with open(log_file_path, 'r') as f:
            lines = f.readlines()
            # Get last 100 lines and reverse order for display (newest first)
            last_100_lines = lines[-100:]
            last_100_lines.reverse()
            
            for line in last_100_lines:
                try:
                    # Generic parsing for standard logging format
                    if " - INFO - " in line or " - ERROR - " in line or " - WARNING - " in line:
                        parts = line.split(' - ', 2)
                        logs.append({"timestamp": parts[0].strip(), "level": parts[1].strip(), "message": parts[2].strip()})
                    elif line.strip():
                        logs.append({"timestamp": "N/A", "level": "RAW", "message": line.strip()})
                except Exception:
                    if line.strip():
                        logs.append({"timestamp": "N/A", "level": "ERROR", "message": line.strip()})
        return jsonify({"logs": logs})
    except Exception as e:
        app.logger.error(f"Error in /api/logs: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/processes")
@admin_required
def api_processes():
    processes = []
    try:
        all_procs = sorted(
            psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'status']),
            key=lambda p: p.info['cpu_percent'],
            reverse=True
        )[:50]

        for proc in all_procs:
            try:
                processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return jsonify({"processes": processes})
    except Exception as e:
        app.logger.error(f"Error in /api/processes: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/network_stats")
@admin_required
def api_network_stats():
    connections = []
    users = []
    try:
        # Get network connections
        for conn in psutil.net_connections():
            if conn.status not in ('ESTABLISHED', 'LISTEN') or not conn.raddr:
                continue
            try:
                p = psutil.Process(conn.pid)
                proc_name = p.name()
                proc_username = p.username()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                proc_name = "N/A"
                proc_username = "N/A"

            connections.append({
                "laddr_ip": conn.laddr.ip,
                "laddr_port": conn.laddr.port,
                "raddr_ip": conn.raddr.ip if conn.raddr else "N/A",
                "raddr_port": conn.raddr.port if conn.raddr else "N/A",
                "status": conn.status,
                "pid": conn.pid,
                "proc_name": proc_name,
                "proc_username": proc_username
            })

        # Get logged in users (SSH/Terminal)
        for user in psutil.users():
            users.append({
                "name": user.name,
                "terminal": user.terminal,
                "host": user.host,
                "started": datetime.fromtimestamp(user.started).strftime('%Y-%m-%d %H:%M:%S')
            })
        
        return jsonify({"connections": connections, "users": users})
    except Exception as e:
        app.logger.error(f"Error in /api/network_stats: {e}")
        return jsonify({"error": str(e)}), 500

def check_service_status(service_name):
    """Checks if a systemd service is active."""
    try:
        result = subprocess.run(
            ['/usr/bin/systemctl', 'is-active', '--quiet', service_name],
            capture_output=True,
            text=True,
            check=False
        )
        
        if result.returncode == 0:
            return 'ACTIVE'
        else:
            return 'INACTIVE' if result.returncode == 3 else 'ERROR'
            
    except FileNotFoundError:
        app.logger.error("systemctl command not found. Cannot check service status.")
        return 'ERROR'
    except Exception as e:
        app.logger.error(f"Error checking service {service_name}: {e}")
        return 'ERROR'

@app.route("/api/service_status")
@admin_required
def api_service_status():
    services = []
    try:
        for service in MONITORED_SERVICES:
            status = check_service_status(service['name'])
            services.append({
                "name": service['name'],
                "display_name": service['display_name'],
                "status": status
            })
        return jsonify({"services": services})
    except Exception as e:
        app.logger.error(f"Error in /api/service_status: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/alerts")
@admin_required
def api_alerts():
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("""
            SELECT id, timestamp, level, message, is_read 
            FROM alerts 
            WHERE is_read = 0
            ORDER BY timestamp DESC 
            LIMIT 100
        """)
        alerts = cursor.fetchall()
        cursor.close()
        
        for alert in alerts:
            alert['timestamp'] = alert['timestamp'].isoformat()
            
        return jsonify({"alerts": alerts})
    except Exception as e:
        app.logger.error(f"Error in /api/alerts: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/alert_dismiss", methods=["POST"])
@admin_required
def api_alert_dismiss():
    try:
        data = request.get_json()
        alert_id = data.get('id')
        if not alert_id:
            return jsonify({"success": False, "error": "Missing alert ID"}), 400
            
        cursor = mysql.connection.cursor()
        cursor.execute("UPDATE alerts SET is_read = 1 WHERE id = %s", (alert_id,))
        mysql.connection.commit()
        cursor.close()
        
        return jsonify({"success": True})
    except Exception as e:
        mysql.connection.rollback()
        app.logger.error(f"Error in /api/alert_dismiss: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/system_overview")
@admin_required
def api_system_overview():
    try:
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        now = datetime.now()
        uptime_delta = now - boot_time
        
        days = uptime_delta.days
        hours, remainder = divmod(uptime_delta.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        uptime_string = f"{days}d, {hours}h, {minutes}m"
        
        disk = psutil.disk_usage('/')
        
        return jsonify({
            "uptime_string": uptime_string,
            "disk_percent": disk.percent,
            "disk_used_gb": bytes_to_gb(disk.used),
            "disk_total_gb": bytes_to_gb(disk.total)
        })
    except Exception as e:
        app.logger.error(f"Error in /api/system_overview: {e}")
        return jsonify({"error": str(e)}), 500

# --- Background Stats Collector Thread ---

def get_network_io(interval=1):
    counter_now = psutil.net_io_counters()
    time.sleep(interval)
    counter_later = psutil.net_io_counters()
    
    sent_bps = counter_later.bytes_sent - counter_now.bytes_sent
    recv_bps = counter_later.bytes_recv - counter_now.bytes_recv
    
    # Convert bits per second to Megabits per second (Mb/s)
    sent_mbps = (sent_bps * 8) / (1024 * 1024) / interval
    recv_mbps = (recv_bps * 8) / (1024 * 1024) / interval
    
    return round(sent_mbps, 2), round(recv_mbps, 2)

def get_disk_io(interval=1):
    counter_now = psutil.disk_io_counters()
    time.sleep(interval)
    counter_later = psutil.disk_io_counters()
    
    read_bytes = counter_later.read_bytes - counter_now.read_bytes
    write_bytes = counter_later.write_bytes - counter_now.write_bytes
    
    # Convert bytes per second to Megabytes per second (MB/s)
    read_mbps = (read_bytes / (1024 * 1024)) / interval
    write_mbps = (write_bytes / (1024 * 1024)) / interval
    
    return round(read_mbps, 2), round(write_mbps, 2)

# Helper to create an alert (used *within* the stats loop)
def create_alert(cursor, level, message):
    try:
        # Check if an identical, unread alert already exists
        cursor.execute(
            "SELECT id FROM alerts WHERE message = %s AND is_read = 0", 
            (message,)
        )
        if cursor.fetchone():
            return # Don't create duplicate unread alerts

        cursor.execute(
            "INSERT INTO alerts (level, message) VALUES (%s, %s)",
            (level, message)
        )
        print(f"Created alert: {level} - {message}")
    except Exception as e:
        print(f"Error creating alert: {e}")

def stats_collector_loop():
    print("Starting background stats collector thread...")
    app.logger.info("Background stats collector thread started.")
    
    # Use Flask application context for database connection
    with app.app_context():
        while True:
            # Short measurement period for accurate I/O calculation
            measurement_interval_sec = 1 
            # Sleep longer to reduce DB load
            sleep_interval_sec = 8 

            try:
                # Use a `with` statement for cursor management
                with mysql.connection.cursor() as cursor:
                    
                    cpu = psutil.cpu_percent(interval=None)
                    mem = psutil.virtual_memory().percent
                    # Get I/O over the measurement interval
                    net_sent, net_recv = get_network_io(measurement_interval_sec)
                    disk_read, disk_write = get_disk_io(measurement_interval_sec)
                    
                    # Get system disk usage for alerting
                    disk = psutil.disk_usage('/')

                    # Insert new system metrics
                    cursor.execute("""
                        INSERT INTO system_stats (cpu_percent, mem_percent, net_sent_mbps, net_recv_mbps, 
                                                  disk_read_mbps, disk_write_mbps)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (cpu, mem, net_sent, net_recv, disk_read, disk_write))
                    
                    # --- Automated Alert Checks ---
                    if cpu > 90:
                        create_alert(cursor, 'ERROR', f'High CPU usage detected: {cpu}%')
                    elif cpu > 75:
                        create_alert(cursor, 'WARNING', f'CPU usage is high: {cpu}%')
                        
                    if mem > 90:
                        create_alert(cursor, 'ERROR', f'High Memory usage detected: {mem}%')
                    elif mem > 75:
                        create_alert(cursor, 'WARNING', f'Memory usage is high: {mem}%')
                        
                    if disk.percent > 90:
                        create_alert(cursor, 'ERROR', f'Critical disk usage: {disk.percent}% full.')
                    elif disk.percent > 80:
                        create_alert(cursor, 'WARNING', f'High disk usage: {disk.percent}% full.')

                    # Check status of monitored services
                    for service in MONITORED_SERVICES:
                        status = check_service_status(service['name'])
                        if status != 'ACTIVE':
                            create_alert(cursor, 'ERROR', f"Service '{service['display_name']}' is {status}.")

                    mysql.connection.commit()
                    
                    # Prune old stats (over 1 hour old)
                    cursor.execute("""
                        DELETE FROM system_stats 
                        WHERE timestamp < (NOW() - INTERVAL 1 HOUR)
                    """)
                    
                    # Prune old, read alerts (over 1 day old)
                    cursor.execute("""
                        DELETE FROM alerts
                        WHERE is_read = 1 AND timestamp < (NOW() - INTERVAL 1 DAY)
                    """)
                    
                    mysql.connection.commit()
                    
            except Exception as e:
                # This catches general exceptions like connection errors outside the cursor block
                print(f"Global error in stats collector thread: {e}")
                app.logger.error(f"Global error in stats collector thread: {e}")
            
            time.sleep(sleep_interval_sec)

# Start the background stats collector
collector_thread = threading.Thread(target=stats_collector_loop, daemon=True)
collector_thread.start()

# --- Main execution ---
if __name__ == "__main__":
    # Note: Flask's default debug mode is NOT thread-safe with the custom collector thread.
    # For production, use a WSGI server (Gunicorn) and set debug=False.
    app.run(debug=True)
