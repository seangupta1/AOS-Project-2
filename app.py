from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, make_response, send_file, jsonify
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re
import os
import mimetypes
from werkzeug.utils import secure_filename
import psutil
import logging
from functools import wraps
import threading
import time
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from backup_manager import BackupManager

app = Flask(__name__)
app.secret_key = 'password'

# --- START LOGGING CONFIG ---
log_file = '/tmp/nas_app.log'
logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
# --- END LOGGING CONFIG ---

# MySQL configuration
# MySQL configuration
app.config['MYSQL_HOST'] = os.environ.get('MYSQL_HOST', 'localhost')
app.config['MYSQL_USER'] = os.environ.get('MYSQL_USER', 'seangupta')
app.config['MYSQL_PASSWORD'] = os.environ.get('MYSQL_PASSWORD', 'password')
app.config['MYSQL_DB'] = os.environ.get('MYSQL_DB', 'nas_web')

# Backup directories
DB_BACKUP_DIR = os.environ.get('DB_BACKUP_DIR', './db_backups')
CONFIG_BACKUP_DIR = os.environ.get('CONFIG_BACKUP_DIR', './config_backups')
CONFIG_FILES_DIR = os.environ.get('CONFIG_FILES_DIR', './config_files')

# Update the Upload folder to be flexible
UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', '/var/www/uploads/')

mysql = MySQL(app)

# Initialize BackupManager
backup_manager = BackupManager(
    db_name=app.config['MYSQL_DB'],
    db_user=app.config['MYSQL_USER'],
    db_password=app.config['MYSQL_PASSWORD'],
    db_host=app.config["MYSQL_HOST"],
    db_backup_dir=DB_BACKUP_DIR,
    config_backup_dir=CONFIG_BACKUP_DIR,
    config_files_dir=CONFIG_FILES_DIR
)

MAX_ATTEMPTS = 3
LOCKOUT_MINUTES = 2

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'loggedin' not in session or session.get('role') != 'admin':
            flash("You do not have permission to access this page.", "error")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

# Helper: check allowed extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# ----------------------------
# FILE UPLOAD
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
    if folder_id in (None, '', 'None'):
        folder_id = None
    else:
        folder_id = int(folder_id)  # ensure it’s an integer

    original_name = secure_filename(file.filename)
    mime_type = file.mimetype or mimetypes.guess_type(original_name)[0]
    size = len(file.read())
    file.seek(0)  # reset stream after reading size

    # Insert DB record first to get file ID
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("""
        INSERT INTO files (user_id, folder_id, original_name, mime_type, size)
        VALUES (%s, %s, %s, %s, %s)
    """, (user_id, folder_id, original_name, mime_type, size))
    mysql.connection.commit()
    file_id = cursor.lastrowid

    # Save file using its DB ID as filename
    ext = os.path.splitext(original_name)[1]
    storage_name = f"{file_id}{ext}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], storage_name)
    file.save(filepath)

    flash('File uploaded successfully.')
    app.logger.info(f"User '{session['username']}' uploaded file '{original_name}'")
    
    if folder_id:
        # stay inside the folder view
        return redirect(url_for('dashboard', folder=folder_id))
    else:
        # return to root dashboard
        return redirect(url_for('dashboard'))


# ----------------------------
# CREATE FOLDER
# ----------------------------
@app.route("/create_folder", methods=["POST"])
def create_folder():
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    folder_name = request.form.get('folder_name')
    parent_id = request.form.get('parent_id')

    if parent_id in (None, '', 'None'):  # <-- convert invalid values
        parent_id = None
    else:
        parent_id = int(parent_id)  # ensure integer

    if not folder_name or folder_name.strip() == '':
        flash("Folder name cannot be empty")
        return redirect(url_for('dashboard'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("""
        INSERT INTO folders (user_id, name, parent_id)
        VALUES (%s, %s, %s)
    """, (session['id'], folder_name.strip(), parent_id))
    mysql.connection.commit()

    flash(f"Folder '{folder_name}' created successfully")
    
    if parent_id:
        # stay inside the folder view
        return redirect(url_for('dashboard', folder=parent_id))
    else:
        # return to root dashboard
        return redirect(url_for('dashboard'))


# ----------------------------
# RENAME FOLDER
# ----------------------------
@app.route("/rename_folder", methods=["POST"])
def rename_folder():
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    folder_name = request.form.get('folder_name')
    folder_id = request.form.get('folder_id')  # optional, can be None
    parent_id = request.form.get('parent_id')

    if folder_id in (None, '', 'None'):  # <-- convert invalid values
        flash("Folder ID can't be None")
        return redirect(url_for('dashboard'))
    else:
        folder_id = int(folder_id)  # ensure integer

    if parent_id in (None, '', 'None'):  # <-- convert invalid values
        parent_id = None
    else:
        parent_id = int(parent_id)  # ensure integer

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

    flash(f"Folder '{folder_name}' renamed successfully")
    
    if parent_id:
        # stay inside the folder view
        return redirect(url_for('dashboard', folder=parent_id))
    else:
        # return to root dashboard
        return redirect(url_for('dashboard'))


# ----------------------------
# DOWNLOAD FOLDER
# ----------------------------
@app.route("/download_folder/<int:folder_id>", methods=["GET"])
def download_folder(folder_id):
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM folders WHERE id = %s AND user_id = %s", (folder_id, session['id']))
    folder_record = cursor.fetchone()

    if not folder_record:
        return "Folder not found or permission denied", 404

    # Build zip in memory
    import io, zipfile, os
    memory_file = io.BytesIO()

    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        # Recursively add all files
        add_folder_to_zip(cursor, zf, folder_id, session['id'], base_path="")

    memory_file.seek(0)

    return send_file(
        memory_file,
        as_attachment=True,
        download_name=f"{folder_record['name']}.zip",
        mimetype='application/zip'
    )


def add_folder_to_zip(cursor, zf, folder_id, user_id, base_path):
    # Get the current folder name
    cursor.execute("SELECT name FROM folders WHERE id = %s", (folder_id,))
    folder = cursor.fetchone()
    folder_name = folder['name'] if folder else f"folder_{folder_id}"
    current_path = os.path.join(base_path, folder_name)

    # Add all files in this folder
    cursor.execute("SELECT id, original_name FROM files WHERE folder_id = %s AND user_id = %s", (folder_id, user_id))
    files = cursor.fetchall()

    for f in files:
        ext = os.path.splitext(f['original_name'])[1]
        storage_name = f"{f['id']}{ext}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], storage_name)

        if os.path.exists(filepath):
            zf.write(filepath, arcname=os.path.join(current_path, f['original_name']))

    # Recurse into subfolders
    cursor.execute("SELECT id FROM folders WHERE parent_id = %s AND user_id = %s", (folder_id, user_id))
    subfolders = cursor.fetchall()

    for sub in subfolders:
        add_folder_to_zip(cursor, zf, sub['id'], user_id, current_path)


# ----------------------------
# DELETE FOLDER
# ----------------------------
@app.route("/delete_folder", methods=["POST"])
def delete_folder():
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    folder_id = request.form.get('folder_id')
    parent_id = request.form.get('parent_id')

    # Validate folder_id
    if not folder_id or folder_id in ('None', ''):
        flash("Folder ID can't be None", "error")
        return redirect(url_for('dashboard'))
    try:
        folder_id = int(folder_id)
    except ValueError:
        flash("Invalid folder ID", "error")
        return redirect(url_for('dashboard'))

    # Convert parent_id
    try:
        parent_id = int(parent_id) if parent_id not in (None, '', 'None') else None
    except ValueError:
        parent_id = None

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT id FROM folders WHERE id = %s AND user_id = %s", (folder_id, session['id']))
    folder_record = cursor.fetchone()

    if not folder_record:
        flash("Folder not found or permission denied", "error")
        return redirect(url_for('dashboard'))

    try:
        delete_folder_recursive(cursor, folder_id, session['id'])
        mysql.connection.commit()
        flash("Folder and its contents deleted successfully.", "success")
    except Exception as e:
        mysql.connection.rollback()
        flash(f"Error deleting folder: {str(e)}", "error")

    # Redirect appropriately
    if parent_id:
        return redirect(url_for('dashboard', folder=parent_id))
    else:
        return redirect(url_for('dashboard'))


def delete_folder_recursive(cursor, folder_id, user_id):
    # Delete subfolders recursively
    cursor.execute("SELECT id FROM folders WHERE parent_id = %s AND user_id = %s", (folder_id, user_id))
    sub_folders = cursor.fetchall()
    for sub in sub_folders:
        delete_folder_recursive(cursor, sub['id'], user_id)

    # Delete all files in this folder
    cursor.execute("DELETE FROM files WHERE folder_id = %s AND user_id = %s", (folder_id, user_id))

    # Finally, delete the folder itself
    cursor.execute("DELETE FROM folders WHERE id = %s AND user_id = %s", (folder_id, user_id))


# ----------------------------
# DASHBOARD
# ----------------------------
@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    
    folder_id = None

    if request.method == "POST":
        folder_id = request.form.get('folder_id')  # <-- get it from form data
        print("Folder ID from POST:", folder_id)
    else:
        folder_id = request.args.get('folder')  # optional: if you also allow query params
        print("Folder ID from GET:", folder_id)
    
    # Convert to integer if needed
    folder_id = int(folder_id) if str(folder_id).isdigit() else None

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    current_folder_id = folder_id
    parent_id = None

    # If inside a subfolder, get its parent_id
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

    response = make_response(render_template(
        "dashboard.html",
        username=session['username'],
        role=session['role'],
        folders=folders,
        files=files,
        current_folder_id=current_folder_id,
        parent_id=parent_id
    ))

    # Prevent caching
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, proxy-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'

    return response


# ----------------------------
# DOWNLOAD FILE
# ----------------------------
@app.route("/download_file/<int:file_id>", methods=["GET"])
def download_file(file_id):
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM files WHERE id = %s AND user_id = %s", (file_id, session['id']))
    file_record = cursor.fetchone()

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


# ----------------------------
# DELETE FILE
# ----------------------------
@app.route("/delete_file", methods=["POST"])
def delete_file():
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    file_id = request.form.get('file_id')
    parent_id = request.form.get('parent_id')

    # Validate file_id
    if not file_id or file_id in ('None', ''):
        flash("File ID can't be None", "error")
        return redirect(url_for('dashboard'))
    try:
        file_id = int(file_id)
    except ValueError:
        flash("Invalid file ID", "error")
        return redirect(url_for('dashboard'))

    # Convert parent_id
    try:
        parent_id = int(parent_id) if parent_id not in (None, '', 'None') else None
    except ValueError:
        parent_id = None

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM files WHERE id = %s AND user_id = %s", (file_id, session['id']))
    file_record = cursor.fetchone()

    if not file_record:
        flash("File not found or permission denied", "error")
        return redirect(url_for('dashboard'))

    # Build file path
    ext = os.path.splitext(file_record['original_name'])[1]
    storage_name = f"{file_id}{ext}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], storage_name)

    try:
        # Delete physical file if it exists
        if os.path.exists(filepath):
            os.remove(filepath)

        # Delete database record
        cursor.execute("DELETE FROM files WHERE id = %s AND user_id = %s", (file_id, session['id']))
        mysql.connection.commit()

        flash("File deleted successfully.", "success")

    except Exception as e:
        mysql.connection.rollback()
        flash(f"Error deleting file: {str(e)}", "error")

    # Redirect back to the correct folder view
    if parent_id:
        return redirect(url_for('dashboard', folder=parent_id))
    else:
        return redirect(url_for('dashboard'))


# ----------------------------
# USER AUTH ROUTES
# ----------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login")
def login():
    return render_template("login.html")

@app.route("/register")
def register():
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
        cursor.execute('SELECT * FROM login_attempts WHERE user_id = %s', (account['id'],))
        attempt_record = cursor.fetchone()

        if attempt_record:
            attempts = attempt_record['attempts']
            last_failed = attempt_record['last_failed']

            if last_failed and isinstance(last_failed, str):
                last_failed = datetime.strptime(last_failed, '%Y-%m-%d %H:%M:%S')

            lockout_end = (last_failed + timedelta(minutes=LOCKOUT_MINUTES)) if last_failed else None
            if lockout_end and now < lockout_end and attempts >= MAX_ATTEMPTS:
                remaining = int((lockout_end - now).total_seconds() // 60) + 1
                msg = f"Account locked. Try again in {remaining} minute(s)."
                return render_template("login.html", msg=msg)
        else:
            cursor.execute("""
                INSERT INTO login_attempts (user_id, attempts, last_failed)
                VALUES (%s, 0, NULL)
            """, (account['id'],))
            mysql.connection.commit()
            attempts = 0
            last_failed = None

        if check_password_hash(account['password'], password):
            # Reset login attempts
            cursor.execute("""
                UPDATE login_attempts
                SET attempts = 0, last_failed = NULL
                WHERE user_id = %s
            """, (account['id'],))
            mysql.connection.commit()

            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            session['role'] = account['role']
            app.logger.info(f"User '{username}' logged in successfully.") 
            return redirect(url_for('dashboard'))
        else:
            # Increment failed login attempts
            attempts += 1
            cursor.execute("""
                UPDATE login_attempts
                SET attempts = %s, last_failed = %s
                WHERE user_id = %s
            """, (attempts, now, account['id']))
            mysql.connection.commit()

            if attempts >= MAX_ATTEMPTS:
                msg = f"Account locked due to too many failed attempts. Try again in {LOCKOUT_MINUTES} minutes."
            else:
                remaining = MAX_ATTEMPTS - attempts
                msg = f"Invalid password. {remaining} attempt(s) remaining."

            return render_template("login.html", msg=msg)
    else:
        app.logger.warning(f"Failed login attempt for username: {username}")
        return render_template("login.html", msg="Invalid username or password.")
    


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
        hashed_password = generate_password_hash(password)
        cursor.execute('INSERT INTO users (username, password, role) VALUES (%s, %s, %s)', (username, hashed_password, 'user'))
        mysql.connection.commit()
        return redirect(url_for('login'))

    return render_template("register.html", msg=msg)


@app.route("/delete_account", methods=["POST"])
def delete_account():
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    user_id = session['id']
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    try:
        # --- 1️⃣ Delete all user folders recursively ---
        cursor.execute("SELECT id FROM folders WHERE user_id = %s AND parent_id IS NULL", (user_id,))
        top_folders = cursor.fetchall()

        for folder in top_folders:
            delete_folder_recursive(cursor, folder['id'], user_id)

        # --- 2️⃣ Delete all files not in folders (root-level files) ---
        cursor.execute("SELECT id, original_name FROM files WHERE user_id = %s AND folder_id IS NULL", (user_id,))
        root_files = cursor.fetchall()
        for file in root_files:
            ext = os.path.splitext(file['original_name'])[1]
            storage_name = f"{file['id']}{ext}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], storage_name)
            if os.path.exists(filepath):
                os.remove(filepath)
            cursor.execute("DELETE FROM files WHERE id = %s AND user_id = %s", (file['id'], user_id))

        # --- 3️⃣ Delete user record ---
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))

        mysql.connection.commit()

        # --- 4️⃣ Clear session and redirect ---
        session.clear()
        flash("Your account and all associated data have been permanently deleted.")
        return redirect(url_for('login'))

    except Exception as e:
        mysql.connection.rollback()
        flash(f"Error deleting account: {e}")
        return redirect(url_for('dashboard'))


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for('login'))

# ----------------------------
# SYSTEM MONITORING API
# ----------------------------

def bytes_to_gb(bytes_val):
    gb = bytes_val / (1024**3); return round(gb, 2)

@app.route("/api/stats_history")
@admin_required
def api_stats_history():
    """Provides system stats from the last hour."""
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        # Get all stats from the last hour, ordered by time
        cursor.execute("""
            SELECT timestamp, cpu_percent, mem_percent, net_sent_mbps, net_recv_mbps 
            FROM system_stats 
            WHERE timestamp > (NOW() - INTERVAL 1 HOUR)
            ORDER BY timestamp ASC
        """)
        stats = cursor.fetchall()

        # We need to format the data for Chart.js
        # It wants "labels" (timestamps) and "datasets" (the numbers)
        formatted_data = {
            "labels": [s['timestamp'].strftime('%I:%M:%S %p') for s in stats],
            "cpu": [s['cpu_percent'] for s in stats],
            "mem": [s['mem_percent'] for s in stats],
            "net_sent": [s['net_sent_mbps'] for s in stats],
            "net_recv": [s['net_recv_mbps'] for s in stats],
        }
        return jsonify(formatted_data)

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route("/api/stats_snapshot")
def api_stats_snapshot():
    """Provides a single, current snapshot of system stats."""
    try:
        # Use root '/' for disk usage, as it's more reliable in Docker
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
        return jsonify({"error": str(e)}), 500

@app.route("/api/logs")
@admin_required
def api_logs():
    """Provides last 50 lines of the application log as JSON objects."""
    if 'loggedin' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    log_file_path = '/tmp/nas_app.log' # <-- The correct path
    logs = []

    try:
        if not os.path.exists(log_file_path):
             # Create the file if it doesn't exist
            with open(log_file_path, 'a') as f:
                f.write("Log file created.\n")
            return jsonify({"logs": []})

        with open(log_file_path, 'r') as f:
            # Read all lines and get the last 50
            lines = f.readlines()
            last_50_lines = lines[-50:]
            last_50_lines.reverse() # Show newest first
            
            for line in last_50_lines:
                try:
                    # Parse the log line based on our format:
                    # '2025-11-04 11:10:00,123 - INFO - User 'admin' logged in'
                    parts = line.split(' - ', 2)
                    logs.append({
                        "timestamp": parts[0].strip(),
                        "level": parts[1].strip(),
                        "message": parts[2].strip()
                    })
                except Exception:
                    # If a line doesn't match, just add it as a raw message
                    if line.strip():
                        logs.append({
                            "timestamp": "N/A",
                            "level": "RAW",
                            "message": line.strip()
                        })

        return jsonify({"logs": logs})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/logs")
@admin_required
def logs():
    """Serves the dedicated log page."""
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    
    return render_template("logs.html")

# ----------------------------
# BACKUPS API
# ----------------------------

@app.route('/admin/configurations')
def configurations_page():
    return render_template("configurations.html")

configs = {
    "email_notifications": True,
    "auto_backup": False,
    "dark_mode": False
}

@app.route('/backup/db', methods=['GET'])
def manual_db_backup():
    backup_file = backup_manager.backup_database()
    if backup_file:
        return send_file(backup_file, as_attachment=True)
    return jsonify({"status": "error", "message": "DB backup failed"}), 500

@app.route('/backup/config', methods=['GET'])
def manual_config_backup():
    backup_file = backup_manager.backup_configurations()
    if backup_file:
        return send_file(backup_file, as_attachment=True)
    return jsonify({"status": "error", "message": "Config backup failed"}), 500

@app.route('/backup/start', methods=['GET'])
def start_auto_backup():
    backup_manager.start_auto_backup(interval_minutes=1)
    return jsonify({"status": "success", "message": "Automatic backups started every minute"})

@app.route('/backup/stop', methods=['GET'])
def stop_auto_backup():
    backup_manager.stop_auto_backup()
    return jsonify({"status": "success", "message": "Automatic backups stopped"})

@app.route('/api/get_configs', methods=['GET'])
def api_get_configs():
    """Return current configuration values."""
    return jsonify({"configs": configs})

@app.route('/api/update_configs', methods=['POST'])
def api_update_configs():
    """Update configuration values from admin page."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid request"}), 400

    for key in configs.keys():
        if key in data:
            configs[key] = bool(data[key])


    if 'auto_backup' in data:
        if configs['auto_backup']:
            backup_manager.start_auto_backup(interval_minutes=1)
        else:
            backup_manager.stop_auto_backup()

    return jsonify({"success": True})

# --- BACKGROUND STATS COLLECTOR ---

def get_network_io():
    """Returns network I/O in Megabits per second (Mbps)."""
    # Get counters now
    counter_now = psutil.net_io_counters()
    time.sleep(1) # Wait 1 second
    # Get counters after 1 second
    counter_later = psutil.net_io_counters()

    # Calculate bytes per second
    sent_bps = counter_later.bytes_sent - counter_now.bytes_sent
    recv_bps = counter_later.bytes_recv - counter_now.bytes_recv

    # Convert bytes/sec to Megabits/sec
    sent_mbps = (sent_bps * 8) / (1024 * 1024)
    recv_mbps = (recv_bps * 8) / (1024 * 1024)

    return round(sent_mbps, 2), round(recv_mbps, 2)

def stats_collector_loop():
    """A background thread loop that collects stats every 10 seconds."""
    print("Starting background stats collector thread...")
    with app.app_context(): # We need an app context to access the database
        while True:
            try:
                cpu = psutil.cpu_percent(interval=None)
                mem = psutil.virtual_memory().percent
                net_sent, net_recv = get_network_io()

                # Connect to DB and insert
                cursor = mysql.connection.cursor()
                cursor.execute("""
                    INSERT INTO system_stats (cpu_percent, mem_percent, net_sent_mbps, net_recv_mbps)
                    VALUES (%s, %s, %s, %s)
                """, (cpu, mem, net_sent, net_recv))
                mysql.connection.commit()

                # Also, clean up old data (older than 1 hour)
                cursor.execute("""
                    DELETE FROM system_stats 
                    WHERE timestamp < (NOW() - INTERVAL 1 HOUR)
                """)
                mysql.connection.commit()
                cursor.close()

            except Exception as e:
                print(f"Error in stats collector thread: {e}")

            time.sleep(10) # Wait 10 seconds before next collection

# --- START THE THREAD ---
collector_thread = threading.Thread(target=stats_collector_loop, daemon=True)
collector_thread.start()

@app.route("/monitoring")
@admin_required
def monitoring():
    """Serves the dedicated monitoring chart page."""
    return render_template("monitoring.html")

if __name__ == "__main__":
    app.run(debug=True)
