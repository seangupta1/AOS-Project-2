# NAS Web App (AOS-Project-2)

This is a secure web application for uploading, downloading, and managing your personal files, built with Flask and MySQL.

## 🚀 Setup Guide (for Beginners)

This guide will walk you through setting up this project on a new Ubuntu/Debian server.

### Part 1: Install Server Software

Install the main components:

1.  **MySQL:** The database.
2.  **Python:** The app's language.
3.  **Apache2:** The web server.
4.  **Git:** The code downloader.

<!-- end list -->

```bash
sudo apt update
sudo apt install -y mysql-server python3-venv python3-pip apache2 git
```

### Part 2: Set Up the Database

1.  Log in to MySQL as the root user:

    ```bash
    sudo mysql
    ```

2.  Paste these commands into the MySQL prompt one by one. **Create a strong, unique password** where it says `YOUR_STRONG_PASSWORD`.

    ```sql
    CREATE DATABASE nas_web;
    CREATE USER 'nas_user'@'localhost' IDENTIFIED BY 'YOUR_STRONG_PASSWORD';
    GRANT ALL PRIVILEGES ON nas_web.* TO 'nas_user'@'localhost';
    FLUSH PRIVILEGES;
    EXIT;
    ```

    *(You will need this password in the next step).*

### Part 3: Set Up the Application

1.  "Clone" (download) the project code:

    ```bash
    sudo git clone https://github.com/seangupta1/AOS-Project-2.git /var/www/nas_app
    ```

2.  Create the folder where your uploaded files will be stored:

    ```bash
    sudo mkdir -p /var/www/uploads
    ```

3.  **Configure the app.** Open the main app file:

    ```bash
    sudo nano /var/www/nas_app/app.py
    ```

    Find this line (around line 35):
    `app.config['MYSQL_PASSWORD'] = os.environ.get('MYSQL_PASSWORD', 'supersecretpassword')`

    Change `'supersecretpassword'` to the `'YOUR_STRONG_PASSWORD'` you created in Part 2. Save and exit (`Ctrl+X`, `Y`, `Enter`).

4.  **Install the app's Python libraries.**

    ```bash
    cd /var/www/nas_app
    sudo python3 -m venv venv
    sudo venv/bin/pip install -r requirements.txt
    ```

5.  **Run the Database Setup Script.** This creates all your tables and the default `admin` account.

    ```bash
    mysql -u nas_user -p nas_web < init_db.sql
    ```

    (It will ask for the `'YOUR_STRONG_PASSWORD'` from Part 2).

### Part 4: Set Up the Server

This is the final part. We'll set everything to run as the default web user, `www-data`.

1.  **Fix Permissions.** Give the `www-data` user ownership of all the project and upload files.

    ```bash
    sudo chown -R www-data:www-data /var/www/nas_app
    sudo chown -R www-data:www-data /var/www/uploads
    ```

2.  **Create the Apache Config.** This tells Apache how to find your app.

      * Create the file:
        ```bash
        sudo nano /etc/apache2/sites-available/nas_app.conf
        ```
      * Paste this in. It should work without changes.
        ```apache
        ServerName localhost
        <VirtualHost *:80>
            ServerName my-nas-server
            Alias /static /var/www/nas_app/static
            <Directory /var/www/nas_app/static>
                Require all granted
            </Directory>
            ProxyPreserveHost On
            ProxyPass / http://127.0.0.1:8000/
            ProxyPassReverse / http://127.0.0.1:8000/
        </VirtualHost>
        ```

3.  **Create the `wsgi.py` file.** This is the "entry point" for the app.

      * Create the file:
        ```bash
        sudo nano /var/www/nas_app/wsgi.py
        ```
      * Paste this in. It should work without changes.
        ```python
        import sys
        import os
        sys.path.insert(0, '/var/www/nas_app')
        from app import app
        application = app
        ```

4.  **Create the Service File.** This makes your app run automatically.

      * Create the file:
        ```bash
        sudo nano /etc/systemd/system/nas_app.service
        ```
      * Paste this in. **This version is generic and does not need to be edited.**
        ```ini
        [Unit]
        Description=Gunicorn instance to serve the NAS Web App
        After=network.target

        [Service]
        User=www-data
        Group=www-data

        WorkingDirectory=/var/www/nas_app
        ExecStart=/var/www/nas_app/venv/bin/gunicorn --workers 3 --bind 127.0.0.1:8000 wsgi:application
        Restart=always

        [Install]
        WantedBy=multi-user.target
        ```

### Part 5: Launch\!

Run these commands to turn everything on.

```bash
# 1. Enable Apache modules
sudo a2enmod proxy proxy_http
sudo a2ensite nas_app.conf
sudo a2dissite 000-default.conf

# 2. Reload all the config files
sudo systemctl daemon-reload

# 3. Start your app and Apache
sudo systemctl start nas_app.service
sudo systemctl restart apache2

# 4. (Optional) Make your app start on boot
sudo systemctl enable nas_app.service
```

Your application is now live\! You can access it by visiting your server's IP address in a browser.

-----

## ❗️ **SECURITY WARNING**

You have just created a default admin account with the credentials:

  * **Username:** `admin`
  * **Password:** `password`

You **MUST** change this immediately.

1.  Log in to your server and run this command:
    ```bash
    /var/www/nas_app/venv/bin/python3 -c "from werkzeug.security import generate_password_hash; print(generate_password_hash(input('Enter new admin password: ')))"
    ```
2.  Enter and confirm your new, secure password.
3.  Copy the hash it gives you (it starts with `pbkdf2:sha256...`).
4.  Log in to MySQL (`sudo mysql`) and run this command to update your password:
    ```sql
    USE nas_web;
    UPDATE users SET password = 'PASTE_YOUR_NEW_HASH_HERE' WHERE username = 'admin';
    EXIT;
    ```
5.  Restart your app to be safe:
    ```bash
    sudo systemctl restart nas_app.service
    ```
