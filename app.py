from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, make_response, send_file
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re
import os
import mimetypes
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'password'

# MySQL configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'seangupta'
app.config['MYSQL_PASSWORD'] = 'password'
app.config['MYSQL_DB'] = 'nas_web'

mysql = MySQL(app)

# Upload configuration
UPLOAD_FOLDER = '/var/www/uploads/'
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
                print(f"Deleted file: {filepath}")
        except Exception as e:
            print(f"Error deleting {filepath}: {e}")

    # Delete file records from the DB
    cursor.execute("DELETE FROM files WHERE folder_id = %s AND user_id = %s", (folder_id, user_id))

    # Delete the folder itself
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
    cursor.execute('SELECT * FROM users WHERE username = %s AND password = %s', (username, password))
    account = cursor.fetchone()

    if account:
        session['loggedin'] = True
        session['id'] = account['id']
        session['username'] = account['username']
        session['role'] = account['role']
        return redirect(url_for('dashboard'))
    else:
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
        cursor.execute('INSERT INTO users (username, password, role) VALUES (%s, %s, %s)', (username, password, 'user'))
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


if __name__ == "__main__":
    app.run(debug=True)
