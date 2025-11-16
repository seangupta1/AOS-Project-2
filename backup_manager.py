import os
import subprocess
import json
import zipfile
import MySQLdb
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
        self.current_interval = 1

        self.settings_file = "./config_settings.json"
        self._ensure_settings_file()
    
    def _ensure_settings_file(self):
        if not os.path.exists(self.settings_file):
            with open(self.settings_file, "w") as f:
                json.dump({"max_backups": 20, "backup_frequency": 5}, f)

    def _load_settings(self):
        with open(self.settings_file, "r") as f:
            return json.load(f)
    
    def _save_settings(self, data):
        with open(self.settings_file, "w") as f:
            json.dump(data, f, indent=4)

    # -------- Max backups --------
    def get_max_backups(self):
        value = self._load_settings().get("max_backups", 20)
        # Allow unlimited backups
        if isinstance(value, str) and value.lower() == "unlimited":
            return "unlimited"
        return int(value)

    def set_max_backups(self, value):
        data = self._load_settings()
        data["max_backups"] = value  # can be int or "unlimited"
        self._save_settings(data)


    # -------- Backup frequency --------
    def get_backup_frequency(self):
        return self._load_settings().get("backup_frequency", 5)

    def set_backup_frequency(self, value):
        data = self._load_settings()
        data["backup_frequency"] = value
        self._save_settings(data)
    
    def enforce_backup_limit(self):
        max_allowed = self.get_max_backups()

        if max_allowed == "unlimited":
            return  # do nothing

        backups = sorted(os.listdir(self.db_backup_dir))  # oldest → newest
        if len(backups) <= max_allowed:
            return

        excess = len(backups) - max_allowed
        for filename in backups[:excess]:
            try:
                os.remove(os.path.join(self.db_backup_dir, filename))
                print(f"[Cleanup] Deleted old backup: {filename}")
            except Exception as e:
                print(f"[Cleanup Error] {filename} -> {e}")

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

            self.enforce_backup_limit()
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

    # ================= Restore Database =================
    def restore_database(self, backup_file):
        try:
            result = subprocess.run(
                [
                    "mysql",
                    f"--user={self.db_user}",
                    f"--password={self.db_password}",
                    f"--host={self.db_host}",
                    self.db_name
                ],
                stdin=open(backup_file, "r"),
                stderr=subprocess.PIPE,
                check=True
            )
            print(f"[DB Restore] Restored from {backup_file}")
            return True
        except subprocess.CalledProcessError as e:
            print("[DB Restore Error]", e.stderr.decode())
            return False
        except Exception as e:
            print("[DB Restore Unexpected Error]", e)
            return False
        
    # ================= Delete Backup =================
    def delete_backup(self, filename):
        backup_path = os.path.join(self.db_backup_dir, filename)
        if os.path.exists(backup_path):
            try:
                os.remove(backup_path)
                print(f"[Backup Delete] Deleted {filename}")
                return True
            except Exception as e:
                print(f"[Backup Delete Error] {e}")
                return False
        else:
            print(f"[Backup Delete] File not found: {filename}")
            return False
        
    # ================= Scheduler Control =================
    def update_interval(self, new_interval):
        """Restart scheduler with a new backup interval."""
        self.current_interval = new_interval

        if self.auto_backups_enabled:
            self.stop_auto_backup()
            self.start_auto_backup(new_interval)

     # ================= List Backups =================
    def list_db_backups(self):
        return sorted(os.listdir(self.db_backup_dir)) if os.path.exists(self.db_backup_dir) else []

    def get_backup_path(self, filename):
        return os.path.join(self.db_backup_dir, filename)
    
    # ================= Automatic Backups =================
    def start_auto_backup(self, interval_minutes=1):
         # If jobs exist, remove them first
        if self.auto_backups_enabled:
            self.stop_auto_backup()

        self.scheduler.add_job(self.backup_database, 'interval', minutes=interval_minutes, id='db_backup')
        self.scheduler.add_job(self.backup_configurations, 'interval', minutes=interval_minutes, id='config_backup')
        if not self.scheduler.running:
            self.scheduler.start()
        self.auto_backups_enabled = True
        self.current_interval = interval_minutes
        print(f"[Backup] Automatic backups enabled every {interval_minutes} minute(s)")

    def stop_auto_backup(self):
        try:
            self.scheduler.remove_job('db_backup')
            self.scheduler.remove_job('config_backup')
        except Exception:
            pass
        self.auto_backups_enabled = False
        print("[Backup] Automatic backups disabled")






        
