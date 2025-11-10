# AOS-Project-2

## Project Setup

You must create the database and initialize the tables before running the application.

1.  Log in to your MySQL server (using the `mysql` command line or a GUI).
2.  Create the database and a dedicated user (as configured in `app.py`):

    ```sql
    CREATE DATABASE nas_web;
    CREATE USER 'nas_user'@'localhost' IDENTIFIED BY 'supersecretpassword';
    GRANT ALL PRIVILEGES ON nas_web.* TO 'nas_user'@'localhost';
    FLUSH PRIVILEGES;
    ```

3.  Use the database and run the following commands to create the tables. (Note: Foreign keys ensure proper data deletion when a user is removed.)

    ```sql
    USE nas_web;

    CREATE TABLE `users` (
      `id` int NOT NULL AUTO_INCREMENT,
      `username` varchar(50) NOT NULL,
      `password` varchar(255) NOT NULL,
      `role` enum('admin','user') DEFAULT 'user',
      `quota_gb` int DEFAULT '20',
      PRIMARY KEY (`id`),
      UNIQUE KEY `username` (`username`)
    );

    CREATE TABLE `folders` (
      `id` int NOT NULL AUTO_INCREMENT,
      `user_id` int NOT NULL,
      `name` varchar(255) NOT NULL,
      `parent_id` int DEFAULT NULL,
      `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (`id`),
      KEY `parent_id` (`parent_id`),
      KEY `user_id_fk` (`user_id`),
      CONSTRAINT `folders_ibfk_1` FOREIGN KEY (`parent_id`) REFERENCES `folders` (`id`),
      CONSTRAINT `folders_user_fk` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
    );

    CREATE TABLE `files` (
      `id` int NOT NULL AUTO_INCREMENT,
      `user_id` int NOT NULL,
      `folder_id` int DEFAULT NULL,
      `original_name` varchar(255) NOT NULL,
      `mime_type` varchar(100) DEFAULT NULL,
      `size` bigint DEFAULT NULL,
      `uploaded_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (`id`),
      KEY `folder_id` (`folder_id`),
      KEY `user_id_fk` (`user_id`),
      CONSTRAINT `files_ibfk_1` FOREIGN KEY (`folder_id`) REFERENCES `folders` (`id`),
      CONSTRAINT `files_user_fk` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
    );

    CREATE TABLE `system_stats` (
      `id` int NOT NULL AUTO_INCREMENT,
      `timestamp` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
      `cpu_percent` float DEFAULT NULL,
      `mem_percent` float DEFAULT NULL,
      `net_sent_mbps` float DEFAULT NULL,
      `net_recv_mbps` float DEFAULT NULL,
      `disk_read_mbps` float DEFAULT NULL,
      `disk_write_mbps` float DEFAULT NULL,
      PRIMARY KEY (`id`)
    );

    CREATE TABLE `alerts` (
      `id` int NOT NULL AUTO_INCREMENT,
      `timestamp` datetime DEFAULT CURRENT_TIMESTAMP,
      `level` varchar(20) NOT NULL,
      `message` text NOT NULL,
      `is_read` tinyint(1) DEFAULT '0',
      PRIMARY KEY (`id`)
    );
    ```

---

## ⚙️ Application & Deployment Setup

### 1. Code Installation and Dependencies

1.  **Clone/Place the project** files into a directory (e.g., `/var/www/nas_app`).
2.  **Install Python requirements:** Create a virtual environment and install dependencies.
    ```bash
    cd /var/www/nas_app
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```
3.  **Create Upload/Log Locations:** Ensure the web server user (`www-data`) has full permissions for the application's required directories.
    ```bash
    sudo mkdir -p /var/www/uploads/
    sudo touch /tmp/nas_app.log
    sudo chown -R www-data:www-data /var/www/uploads/
    sudo chown www-data:www-data /tmp/nas_app.log
    ```

### 2. Gunicorn Service (Systemd)

Create a systemd service to run Gunicorn robustly in the background, listening on `127.0.0.1:8000` for Apache.

* You must create a service file named `/etc/systemd/system/nas_app.service` and enable it using `sudo systemctl enable nas_app.service`.

### 3. Apache Reverse Proxy

1.  Copy the provided **`apache.conf`** file to the Apache sites directory:
    ```bash
    sudo cp /var/www/nas_app/apache.conf /etc/apache2/sites-available/nas_app.conf
    ```
2.  Enable the necessary modules (`proxy_http`) and the site, then restart Apache:
    ```bash
    sudo a2enmod proxy proxy_http
    sudo a2ensite nas_app.conf
    sudo a2dissite 000-default.conf # Recommended
    sudo systemctl restart apache2
    ```