import os
from flask import Blueprint, request, redirect, url_for, render_template, flash, current_app, jsonify
from backup_manager import BackupManager
from utils import admin_required

backup_bp = Blueprint("backup", __name__)


# Construct your manager (or inject via app factory)
manager = BackupManager(
    db_name = os.environ.get('MYSQL_DB', 'nas_web'),
    db_user = os.environ.get('MYSQL_USER', 'nas_user'),
    db_password = os.environ.get('MYSQL_PASSWORD', 'supersecretpassword'),
    db_host = os.environ.get('MYSQL_HOST', 'localhost')
)

DB_BACKUP_DIR = os.environ.get('DB_BACKUP_DIR', './db_backups')
CONFIG_BACKUP_DIR = os.environ.get('CONFIG_BACKUP_DIR', './config_backups')
CONFIG_FILES_DIR = os.environ.get('CONFIG_FILES_DIR', './config_files')


# ---------------- PAGE VIEW ----------------
@backup_bp.route("/backups", methods=["GET"])
@admin_required
def backups_page():
    backups = manager.list_db_backups()
    freq = manager.get_backup_frequency()
    max_backups = manager.get_max_backups()

    return render_template(
        "backups.html",
        backups=backups,
        backup_frequency=freq,
        max_backups=max_backups
    )

@backup_bp.route("/backups/list", methods=["GET"])
def backups_list():
    backups = manager.list_db_backups()
    return render_template('backups_list.html', backups=backups)


@backup_bp.route("/backups/backup", methods=["POST"])
@admin_required
def perform_backup():
    file = manager.backup_database()
    if file:
        print("Backup created successfully.")
    else:
        print("Backup failed.")
    return redirect(url_for("backup.backups_page"))


@backup_bp.route("/backups/manual_backup", methods=["POST"])
@admin_required
def perform_manual_backup():
    file = manager.backup_database()
    if file:
        flash("Backup created successfully.")
        print("Backup created successfully.")
    else:
        flash("Backup failed.")
        print("Backup failed.")
    return redirect(url_for("backup.backups_page"))

# -----------------------------
# AUTOMATIC BACKUP CONTROL
# -----------------------------
@backup_bp.route("/backups/auto/start", methods=["POST"])
@admin_required
def start_auto_backup():
    interval = request.form.get("interval")
    if not interval:
        flash("Please enter a backup interval.")
        return redirect(url_for("backup.backups_page"))
    try:
        interval = int(interval)
    except ValueError:
        flash("Invalid interval value.")
        return redirect(url_for("backup.backups_page"))

    manager.start_auto_backup(interval_minutes=interval)
    manager.set_backup_frequency(interval)
    flash(f"Automatic backups started every {interval} minute(s).")
    return redirect(url_for("backup.backups_page"))

@backup_bp.route("/backups/auto/stop", methods=["POST"])
@admin_required
def stop_auto_backup():
    manager.stop_auto_backup()
    flash("Automatic backups stopped.")
    print("Automatic backups stopped.")
    return redirect(url_for("backup.backups_page"))

# -----------------------------
# CONFIG BACKUP
# -----------------------------
@backup_bp.route("/backups/config", methods=["POST"])
@admin_required
def perform_config_backup():
    file = manager.backup_configurations()
    if file:
        flash("Configuration backup created successfully.")
        print("Configuration backup created successfully.")
    else:
        flash("Backup failed.")
        print("Backup failed.")

    return redirect(url_for("backup.backups_page"))


# ---------------- CHANGE FREQUENCY ----------------
@backup_bp.route("/set-backup-frequency", methods=["POST"])
@admin_required
def change_frequency():
    freq = int(request.form["frequency"])
    manager.set_backup_frequency(freq)
    manager.update_interval(freq)

    flash(f"Automatic backup frequency updated to {freq} minute(s).")
    return redirect(url_for("backup.backups_page"))


# ---------------- RESTORE BACKUP ----------------
@backup_bp.route("/backups/restore", methods=["POST"])
@admin_required
def restore_backup():
    filename = request.form["filename"]
    path = manager.get_backup_path(filename)

    if manager.restore_database(path):
        flash(f"Database restored from {filename}")
        print(f"Database restored from {filename}")

    else:
        flash("Restore failed.")
        print("Restore failed.")


    return redirect(url_for("backup.backups_page"))

# ---------------- DELETE BACKUP ----------------
@backup_bp.route("/backups/delete", methods=["POST"])
@admin_required
def delete_backup():
    filename = request.form.get('filename')
    
    if not filename:
        flash("No backup selected for deletion.", "error")
        return redirect(url_for('backup.list_backups'))
    
    success = manager.delete_backup(filename)
    if success:
        flash(f'Backup "{filename}" deleted successfully.', 'success')
    else:
        flash(f'Failed to delete backup "{filename}".', 'error')
    
    return redirect(url_for('backup.backups_page'))


### Admin confiugration backups
# In-memory backup-related configs
backup_configs = {
    "auto_backup": False,
    "email_notifications": True,
    "dark_mode": False
}

@backup_bp.route("/backups/configs", methods=['GET'])
@admin_required
def get_backup_configs():
    """Return current backup-related configurations."""
    return jsonify({"configs": backup_configs})

import MySQLdb

@backup_bp.route("/backups/configs", methods=['POST'])
@admin_required
def update_backup_configs():
    """Update backup-related configurations from admin page."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid request"}), 400

    for key in backup_configs.keys():
        if key in data:
            backup_configs[key] = bool(data[key])

    # Persist to database
    # This correctly uses your main app's credentials
    conn = MySQLdb.connect(
        host=os.environ.get('MYSQL_HOST', 'localhost'),
        user=os.environ.get('MYSQL_USER', 'nas_user'),
        passwd=os.environ.get('MYSQL_PASSWORD', 'supersecretpassword'),
        db=os.environ.get('MYSQL_DB', 'nas_web')
    )
    cursor = conn.cursor()
    for key, value in backup_configs.items():
        cursor.execute("""
            INSERT INTO app_config (config_key, config_value)
            VALUES (%s, %s)
            ON DUPLICATE KEY UPDATE config_value = %s
        """, (key, value, value))
    conn.commit()
    cursor.close()
    conn.close()

    # Apply auto_backup setting immediately
    if 'auto_backup' in data:
        if backup_configs['auto_backup']:
            manager.start_auto_backup(interval_minutes=1)
        else:
            manager.stop_auto_backup()

    return jsonify({"success": True})

@backup_bp.route("/backups/max", methods=["POST"])
@admin_required
def set_max_backups():
    raw = request.form["max_backups"].strip()
    if raw.lower() == "unlimited":
        manager.set_max_backups("unlimited")
        return redirect(url_for("backup.backups_page"))

    else:
        try:
            num = int(raw)
            manager.set_max_backups(num)
            manager.enforce_backup_limit()
            return redirect(url_for("backup.backups_page"))
        except ValueError:
            flash("Invalid max backup value. Use a number or 'unlimited'.")
            return redirect(url_for("backup.backups_page"))
    