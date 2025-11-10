from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, make_response, send_file, jsonify
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re
import os
import mimetypes
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash # Added for security
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

app = Flask(__name__)
app.secret_key = 'password'

# Application-wide logging configuration
log_file = '/tmp/nas_app.log'
logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# MySQL database configuration
app.config['MYSQL_HOST'] = os.environ.get('MYSQL_HOST', 'localhost')
app.config['MYSQL_USER'] = os.environ.get('MYSQL_USER', 'nas_user')
app.config['MYSQL_PASSWORD'] = os.environ.get('MYSQL_PASSWORD', 'supersecretpassword')
app.config['MYSQL_DB'] = os.environ.get('MYSQL_DB', 'nas_web')

mysql = MySQL(app)

# File upload configuration
UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', '/var/www/uploads/')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov', 'zip', 'doc', 'docx', 'xls', 'xlsx'}

# Services to monitor on the admin panel (assumes systemd)
MONITORED_SERVICES = [
    {"name": "mysql.service", "display_name": "Database (MySQL)"},
    {"name": "ssh", "display_name": "SSH Server"},
    # Add other services like 'nginx' or 'gunicorn' as needed
]

# Decorator to protect routes that require admin privileges
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'loggedin' not in session or session.get('role') != 'admin':
            flash("You do not have permission to access this page.", "error")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Helper: check allowed extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ----------------------------
# FILE & FOLDER ROUTES
# ----------------------------

@app.route("/upload_file", methods=["POST"])
def upload_file():
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    
    file = request.files['file']
    
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
    
    if not allowed_file(file.filename):
        flash('Invalid file type.')
        return redirect(request.url)

    user_id = session['id']
    folder_id = request.form.get('folder_id')
    folder_id = int(folder_id) if str(folder_id).isdigit() else None

    # Check if the user has enough quota for this upload
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT quota_gb FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    user_quota_bytes = (user['quota_gb'] or 20) * 1024**3 
    cursor.execute("SELECT SUM(size) as total_usage FROM files WHERE user_id = %s", (user_id,))
    usage = cursor.fetchone()
    current_usage_bytes = usage['total_usage'] or 0
    
    new_file_size = len(file.read())
    file.seek(0) 

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

    cursor.execute("""
        INSERT INTO files (user_id, folder_id, original_name, mime_type, size)
        VALUES (%s, %s, %s, %s, %s)
    """, (user_id, folder_id, original_name, mime_type, size))
    mysql.connection.commit()
    file_id = cursor.lastrowid
    cursor.close()

    ext = os.path.splitext(original_name)[1]
    storage_name = f"{file_id}{ext}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], storage_name)
    file.save(filepath)

    flash('File uploaded successfully.')
    app.logger.info(f"User '{session['username']}' uploaded file '{original_name}'")
    
    if folder_id:
        return redirect(url_for('dashboard', folder=folder_id))
    else:
        return redirect(url_for('dashboard'))

@app.route("/create_folder", methods=["POST"])
def create_folder():
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    folder_name = request.form.get('folder_name')
    parent_id = request.form.get('parent_id')
    parent_id = int(parent_id) if str(parent_id).isdigit() else None

    if not folder_name or folder_name.strip() == '':
        flash("Folder name cannot be empty")
        return redirect(url_for('dashboard'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("""
        INSERT INTO folders (user_id, name, parent_id)
        VALUES (%s, %s, %s)
    """, (session['id'], folder_name.strip(), parent_id))
    mysql.connection.commit()
    cursor.close()
    flash(f"Folder '{folder_name}' created successfully")
    
    if parent_id:
        return redirect(url_for('dashboard', folder=parent_id))
    else:
        return redirect(url_for('dashboard'))

@app.route("/rename_folder", methods=["POST"])
def rename_folder():
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    folder_name = request.form.get('folder_name')
    folder_id = request.form.get('folder_id')
    parent_id = request.form.get('parent_id')

    folder_id = int(folder_id) if str(folder_id).isdigit() else None
    parent_id = int(parent_id) if str(parent_id).isdigit() else None

    if not folder_id:
        flash("Folder ID can't be None")
        return redirect(url_for('dashboard'))
    if not folder_name or folder_name.strip() == '':
        flash("Folder name cannot be empty")
        return redirect(url_for('dashboard'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("""
                    UPDATE folders 
                    SET name = %s 
                    WHERE id = %s AND user_id = %s
    """, (folder_name.strip(), folder_id, session['id']))
    mysql.connection.commit()
    cursor.close()
    flash(f"Folder '{folder_name}' renamed successfully")
    
    if parent_id:
        return redirect(url_for('dashboard', folder=parent_id))
    else:
        return redirect(url_for('dashboard'))

@app.route("/download_folder/<int:folder_id>", methods=["GET"])
def download_folder(folder_id):
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM folders WHERE id = %s AND user_id = %s", (folder_id, session['id']))
    folder_record = cursor.fetchone()
    if not folder_record:
        cursor.close()
        return "Folder not found or permission denied", 404

    memory_file = io.BytesIO()
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
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
def delete_folder():
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    folder_id = request.form.get('folder_id')
    parent_id = request.form.get('parent_id')

    folder_id = int(folder_id) if str(folder_id).isdigit() else None
    parent_id = int(parent_id) if str(parent_id).isdigit() else None

    if not folder_id:
        flash("Folder ID can't be None", "error")
        return redirect(url_for('dashboard'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT id FROM folders WHERE id = %s AND user_id = %s", (folder_id, session['id']))
    folder_record = cursor.fetchone()
    if not folder_record:
        cursor.close()
        flash("Folder not found or permission denied", "error")
        return redirect(url_for('dashboard'))
    try:
        delete_folder_recursive(cursor, folder_id, session['id'])
        mysql.connection.commit()
        flash("Folder and its contents deleted successfully.", "success")
    except Exception as e:
        mysql.connection.rollback()
        flash(f"Error deleting folder: {str(e)}", "error")
    
    cursor.close()
    if parent_id:
        return redirect(url_for('dashboard', folder=parent_id))
    else:
        return redirect(url_for('dashboard'))

def delete_folder_recursive(cursor, folder_id, user_id):
    cursor.execute("SELECT id FROM folders WHERE parent_id = %s AND user_id = %s", (folder_id, user_id))
    sub_folders = cursor.fetchall()
    for sub in sub_folders:
        delete_folder_recursive(cursor, sub['id'], user_id)
    
    cursor.execute("SELECT id, original_name FROM files WHERE folder_id = %s AND user_id = %s", (folder_id, user_id))
    files = cursor.fetchall()
    for file_record in files:
        file_id = file_record['id']
        ext = os.path.splitext(file_record['original_name'])[1]
        storage_name = f"{file_id}{ext}"
        filepath = os.path.join(UPLOAD_FOLDER, storage_name)
        try:
            if os.path.exists(filepath):
                os.remove(filepath)
                print(f"Deleted file: {filepath}")
        except Exception as e:
            print(f"Error deleting {filepath}: {e}")
            
    cursor.execute("DELETE FROM files WHERE folder_id = %s AND user_id = %s", (folder_id, user_id))
    cursor.execute("DELETE FROM folders WHERE id = %s AND user_id = %s", (folder_id, user_id))

@app.route("/dashboard", methods=["GET"])
def dashboard():
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    
    folder_id = request.args.get('folder') 
    
    folder_id = int(folder_id) if str(folder_id).isdigit() else None
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    current_folder_id = folder_id
    parent_id = None

    if current_folder_id is not None:
        cursor.execute(
            "SELECT parent_id FROM folders WHERE id = %s AND user_id = %s",
            (current_folder_id, session['id'])
        )
        folder = cursor.fetchone()
        if folder:
            parent_id = folder['parent_id']
        else:
            flash("Folder not found.")
            cursor.close()
            return redirect(url_for('dashboard'))
        
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
        current_usage_gb=current_usage_gb,
        user_quota_gb=user_quota_gb,
        usage_percent=usage_percent
    ))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, proxy-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route("/download_file/<int:file_id>", methods=["GET"])
def download_file(file_id):
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM files WHERE id = %s AND user_id = %s", (file_id, session['id']))
    file_record = cursor.fetchone()
    cursor.close()
    if not file_record:
        return "File not found or permission denied", 404
    
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
def delete_file():
    if 'loggedin' not in session:
        return redirect(url_for('login'))
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
    except Exception as e:
        mysql.connection.rollback()
        flash(f"Error deleting file: {str(e)}", "error")
        
    cursor.close()
    if parent_id:
        return redirect(url_for('dashboard', folder=parent_id))
    else:
        return redirect(url_for('dashboard'))

# ----------------------------
# USER AUTH ROUTES
# ----------------------------
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
    cursor.close()

    # Check if account exists and password hash matches
    if account and account['password'] == password:
        session['loggedin'] = True
        session['id'] = account['id']
        session['username'] = account['username']
        session['role'] = account['role']
        app.logger.info(f"User '{username}' logged in successfully.")
        return redirect(url_for('dashboard'))
    else:
        app.logger.warning(f"Failed login attempt for username: {username}")
        
        # Create a system alert for failed login attempts
        create_alert_helper('WARNING', f'Failed login attempt for username: {username}')
        
        flash("Invalid username or password.", "error")
        return redirect(url_for('login'))

@app.route("/register_request", methods=["POST"])
def register_request():
    username = request.form.get("username")
    password = request.form.get("password")
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
    account = cursor.fetchone()
    if account:
        msg = 'Username already exists!'
    elif not re.match(r'^[A-Za-z0-9]+$', username):
        msg = 'Username must contain only letters and numbers!'
    else:
        # Hash the password before storing it
        hashed_password = generate_password_hash(password)
        cursor.execute('INSERT INTO users (username, password, role) VALUES (%s, %s, %s)', (username, hashed_password, 'user'))
        mysql.connection.commit()
        cursor.close()
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for('login'))
    
    cursor.close()
    return render_template("register.html", msg=msg)

@app.route("/delete_account", methods=["POST"])
def delete_account():
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    user_id = session['id']
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        # With 'ON DELETE CASCADE' in the database,
        # deleting the user will automatically delete their files and folders.
        
        # We still need to manually delete the physical files from the upload folder.
        cursor.execute("SELECT id, original_name FROM files WHERE user_id = %s", (user_id,))
        all_files = cursor.fetchall()
        for file in all_files:
            ext = os.path.splitext(file['original_name'])[1]
            storage_name = f"{file['id']}{ext}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], storage_name)
            if os.path.exists(filepath):
                os.remove(filepath)
            
        # Now, just delete the user. The DB will handle the rest.
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        mysql.connection.commit()
        cursor.close()
        session.clear()
        flash("Your account and all associated data have been permanently deleted.")
        return redirect(url_for('login'))
    except Exception as e:
        mysql.connection.rollback()
        cursor.close()
        flash(f"Error deleting account: {e}")
        return redirect(url_for('dashboard'))

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for('login'))

# ----------------------------------
## Admin Panel & API Routes
# ----------------------------------

# Helper to create an alert from outside the main stats loop
def create_alert_helper(level, message):
    """
    Creates an alert. Handles its own DB connection.
    Used for creating alerts from outside the stats_collector_loop.
    """
    try:
        conn = mysql.connection
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT id FROM alerts WHERE message = %s AND is_read = 0", 
            (message,)
        )
        if cursor.fetchone():
            cursor.close()
            return # Don't create duplicate unread alerts

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

@app.route("/admin_monitoring_panel")
@admin_required
def admin_monitoring_panel():
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        
        # Query for the storage report
        cursor.execute("""
            SELECT 
                users.id, 
                users.username, 
                users.role, 
                users.quota_gb,
                SUM(files.size) as total_usage
            FROM users
            LEFT JOIN files ON users.id = files.user_id
            GROUP BY users.id, users.username, users.role, users.quota_gb
            ORDER BY total_usage DESC
        """)
        users_raw = cursor.fetchall()
        cursor.close()

        # Process the report data
        users_report = []
        for user in users_raw:
            usage_bytes = user['total_usage'] or 0
            quota_gb = user['quota_gb'] if user and user['quota_gb'] is not None else 20
            quota_bytes = quota_gb * 1024**3
            usage_gb = round(usage_bytes / (1024**3), 2)
            percent = 0
            if quota_bytes > 0:
                percent = round((usage_bytes / quota_bytes) * 100, 1)

            users_report.append({
                "id": user['id'],
                "username": user['username'],
                "role": user['role'],
                "usage_gb": usage_gb,
                "quota_gb": quota_gb,
                "percent": percent
            })
        
        return render_template("admin_monitoring_panel.html", users_report=users_report)

    except Exception as e:
        app.logger.error(f"Error in /admin_monitoring_panel: {e}")
        flash(f"Error generating admin panel: {e}", "error")
        return redirect(url_for('dashboard'))

# Admin route to update a user's storage quota
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
        
        flash("User quota updated successfully.", "success")
        app.logger.info(f"Admin '{session['username']}' updated quota for user ID {user_id} to {new_quota} GB.")

    except Exception as e:
        mysql.connection.rollback()
        app.logger.error(f"Error in /update_quota: {e}")
        flash(f"Error updating quota: {e}", "error")
    
    return redirect(url_for('admin_monitoring_panel'))

# API endpoints for the admin monitoring panel

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
            "labels": [s['timestamp'].strftime('%Y-%m-%dT%H:%M:%S') for s in stats], # Use ISO format for date-fns
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
            last_100_lines = lines[-100:]
            last_100_lines.reverse()
            for line in last_100_lines:
                try:
                    if "[INFO]" in line:
                        parts = line.split("[INFO] ", 1)
                        timestamp = parts[0].strip("[]")
                        message = parts[1].strip()
                        logs.append({"timestamp": timestamp, "level": "INFO", "message": message})
                    elif " - INFO - " in line or " - ERROR - " in line or " - WARNING - " in line:
                        parts = line.split(' - ', 2)
                        logs.append({"timestamp": parts[0].strip(), "level": parts[1].strip(), "message": parts[2].strip()})
                    elif "HTTP/1.1" in line:
                            logs.append({"timestamp": "N/A", "level": "ACCESS", "message": line.strip()})
                    elif line.strip():
                        logs.append({"timestamp": "N/A", "level": "RAW", "message": line.strip()})
                except Exception:
                    if line.strip():
                        logs.append({"timestamp": "N/A", "level": "ERROR", "message": line.strip()})
        return jsonify({"logs": logs})
    except Exception as e:
        app.logger.error(f"Error in /api/logs: {e}")
        return jsonify({"error": str(e)}), 500

# API: Get top running processes
@app.route("/api/processes")
@admin_required
def api_processes():
    processes = []
    try:
        # Get all processes, sort by CPU usage, take top 50
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

# API: Get active network connections and logged-in users
@app.route("/api/network_stats")
@admin_required
def api_network_stats():
    connections = []
    users = []
    try:
        # Get network connections
        for conn in psutil.net_connections():
            if conn.status != 'ESTABLISHED' or not conn.raddr:
                continue
            connections.append({
                "laddr_ip": conn.laddr.ip,
                "laddr_port": conn.laddr.port,
                "raddr_ip": conn.raddr.ip,
                "raddr_port": conn.raddr.port,
                "status": conn.status,
                "pid": conn.pid
            })

        # Get logged in users
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
    """Checks if a systemd service is active using subprocess for better error handling."""
    try:
        # Use the absolute path to systemctl for reliability
        result = subprocess.run(
            ['/usr/bin/systemctl', 'is-active', '--quiet', service_name],
            capture_output=True,
            text=True,
            check=False
        )
        
        if result.returncode == 0:
            return 'ACTIVE'
        else:
            if result.stderr:
                app.logger.warning(f"Service check for '{service_name}' failed: {result.stderr.strip()}")
            elif result.returncode == 3:
                 app.logger.warning(f"Service check for '{service_name}' reported status: INACTIVE")
            else:
                 app.logger.warning(f"Service check for '{service_name}' returned unknown code: {result.returncode}")
            return 'INACTIVE' 
            
    except FileNotFoundError:
        app.logger.error("systemctl command not found at '/usr/bin/systemctl'. Cannot check service status.")
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

# API: Get recent system alerts
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

# API: Mark a system alert as 'read'
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

# API: Get system uptime and root disk usage
@app.route("/api/system_overview")
@admin_required
def api_system_overview():
    try:
        # Get Uptime
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        now = datetime.now()
        uptime_delta = now - boot_time
        
        # Format uptime string
        days = uptime_delta.days
        hours, remainder = divmod(uptime_delta.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        uptime_string = f"{days}d, {hours}h, {minutes}m"
        
        # Get System Disk Usage
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

# ----------------------------------
## Background Stats Collector Thread
# ----------------------------------

def get_network_io(interval=1):
    counter_now = psutil.net_io_counters()
    time.sleep(interval)
    counter_later = psutil.net_io_counters()
    
    sent_bps = counter_later.bytes_sent - counter_now.bytes_sent
    recv_bps = counter_later.bytes_recv - counter_now.bytes_recv
    
    sent_mbps = (sent_bps * 8) / (1024 * 1024) / interval
    recv_mbps = (recv_bps * 8) / (1024 * 1024) / interval
    
    return round(sent_mbps, 2), round(recv_mbps, 2)

def get_disk_io(interval=1):
    counter_now = psutil.disk_io_counters()
    time.sleep(interval)
    counter_later = psutil.disk_io_counters()
    
    read_bytes = counter_later.read_bytes - counter_now.read_bytes
    write_bytes = counter_later.write_bytes - counter_now.write_bytes
    
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
    
    with app.app_context():
        while True:
            measurement_interval_sec = 1
            sleep_interval_sec = 8 

            try:
                with mysql.connection.cursor() as cursor:
                    
                    cpu = psutil.cpu_percent(interval=None)
                    mem = psutil.virtual_memory().percent
                    net_sent, net_recv = get_network_io(measurement_interval_sec)
                    disk_read, disk_write = get_disk_io(measurement_interval_sec)
                    
                    # Get system disk usage for alerting
                    disk = psutil.disk_usage('/')

                    cursor.execute("""
                        INSERT INTO system_stats (cpu_percent, mem_percent, net_sent_mbps, net_recv_mbps, 
                                                  disk_read_mbps, disk_write_mbps)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (cpu, mem, net_sent, net_recv, disk_read, disk_write))
                    
                    
                    # Check for high CPU/Memory usage
                    if cpu > 90:
                        create_alert(cursor, 'ERROR', f'High CPU usage detected: {cpu}%')
                    elif cpu > 75:
                        create_alert(cursor, 'WARNING', f'CPU usage is high: {cpu}%')
                        
                    if mem > 90:
                        create_alert(cursor, 'ERROR', f'High Memory usage detected: {mem}%')
                    elif mem > 75:
                        create_alert(cursor, 'WARNING', f'Memory usage is high: {mem}%')
                        
                    # Check for high disk usage
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
                    
                    # Prune old stats
                    cursor.execute("""
                        DELETE FROM system_stats 
                        WHERE timestamp < (NOW() - INTERVAL 1 HOUR)
                    """)
                    
                    # Prune old, read alerts
                    cursor.execute("""
                        DELETE FROM alerts
                        WHERE is_read = 1 AND timestamp < (NOW() - INTERVAL 1 DAY)
                    """)
                    
                    mysql.connection.commit()
                    
            except Exception as e:
                print(f"Error in stats collector thread: {e}")
                app.logger.error(f"Error in stats collector thread: {e}")
            
            time.sleep(sleep_interval_sec)

# Start the background stats collector
collector_thread = threading.Thread(target=stats_collector_loop, daemon=True)
collector_thread.start()

# --- Main execution ---
if __name__ == "__main__":
    app.run(debug=True)