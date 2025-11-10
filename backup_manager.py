import os
import subprocess
import json
import zipfile
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler

class BackupManager:
    def __init__(self, db_name, db_user, db_password, db_host='127.0.0.1',
                 db_backup_dir='./db_backups', config_backup_dir='./config_backups', config_files_dir='./config_files'):
        self.db_name = db_name
        self.db_user = db_user
        self.db_password = db_password
        self.db_host = db_host

        self.db_backup_dir = db_backup_dir
        self.config_backup_dir = config_backup_dir
        self.config_files_dir = config_files_dir

        os.makedirs(self.db_backup_dir, exist_ok=True)
        os.makedirs(self.config_backup_dir, exist_ok=True)
        os.makedirs(self.config_files_dir, exist_ok=True)

        self.scheduler = BackgroundScheduler()
        self.auto_backups_enabled = False

    # ================= Database Backup =================
    def backup_database(self):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_file = os.path.join(self.db_backup_dir, f"{self.db_name}_{timestamp}.sql")

        try:
            subprocess.run(
                [
                    "mysqldump",
                    f"--user={self.db_user}",
                    f"--password={self.db_password}",
                    f"--host={self.db_host}",
                    self.db_name
                ],
                stdout=open(backup_file, "w"),
                stderr=subprocess.PIPE,
                check=True
            )
            print(f"[DB Backup] Success: {backup_file}")
            return backup_file
        except subprocess.CalledProcessError as e:
            print(f"[DB Backup Error] {e.stderr}")
            return None

    # ================= Config Backup =================
    def backup_configurations(self):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_file = os.path.join(self.config_backup_dir, f"config_backup_{timestamp}.zip")

    
        try:
            import MySQLdb
            conn = MySQLdb.connect(host=self.db_host, user=self.db_user, passwd=self.db_password, db=self.db_name)
            cursor = conn.cursor()
            cursor.execute("SELECT config_key, config_value FROM app_config")
            config_data = dict(cursor.fetchall())
            cursor.close()
            conn.close()
        except Exception as e:
            print(f"[Config Backup Error] {e}")
            return None

        # Write zip with JSON + optional config files
        with zipfile.ZipFile(backup_file, 'w') as zipf:
            zipf.writestr("app_config.json", json.dumps(config_data, indent=4))
            if os.path.exists(self.config_files_dir):
                for root, _, files in os.walk(self.config_files_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, self.config_files_dir)
                        zipf.write(file_path, arcname=f"files/{arcname}")

        print(f"[Config Backup] Success: {backup_file}")
        return backup_file

    # ================= Automatic Backups =================
    def start_auto_backup(self, interval_minutes=1):
        if not self.auto_backups_enabled:
            self.scheduler.add_job(self.backup_database, 'interval', minutes=interval_minutes, id='db_backup')
            self.scheduler.add_job(self.backup_configurations, 'interval', minutes=interval_minutes, id='config_backup')
            self.scheduler.start()
            self.auto_backups_enabled = True
            print("[Backup] Automatic backups enabled every", interval_minutes, "minute(s)")

    def stop_auto_backup(self):
        if self.auto_backups_enabled:
            self.scheduler.remove_job('db_backup')
            self.scheduler.remove_job('config_backup')
            self.auto_backups_enabled = False
            print("[Backup] Automatic backups disabled")
