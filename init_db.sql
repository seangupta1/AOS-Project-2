-- Create database if not exists
CREATE DATABASE IF NOT EXISTS nas_web;
USE nas_web;

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id INT NOT NULL AUTO_INCREMENT,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(255) NOT NULL,
    role ENUM('admin', 'user') DEFAULT 'user',
    PRIMARY KEY (id),
    UNIQUE KEY username (username)
);

-- Folders table
CREATE TABLE IF NOT EXISTS folders (
    id INT NOT NULL AUTO_INCREMENT,
    user_id INT NOT NULL,
    name VARCHAR(255) NOT NULL,
    parent_id INT DEFAULT NULL,
    created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY parent_id (parent_id),
    CONSTRAINT folders_ibfk_1 FOREIGN KEY (parent_id) REFERENCES folders (id)
);

-- Files table
CREATE TABLE IF NOT EXISTS files (
    id INT NOT  NULL AUTO_INCREMENT,
    user_id INT NOT NULL,
    folder_id INT DEFAULT NULL,
    original_name VARCHAR(255) NOT NULL,
    mime_type VARCHAR(100) DEFAULT NULL,
    size BIGINT DEFAULT NULL,
    uploaded_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY folder_id (folder_id),
    CONSTRAINT files_ibfk_1 FOREIGN KEY (folder_id) REFERENCES folders (id)
);

-- System monitoring stats table
CREATE TABLE IF NOT EXISTS system_stats (
    id INT NOT NULL AUTO_INCREMENT,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    cpu_percent FLOAT,
    mem_percent FLOAT,
    net_sent_mbps FLOAT,
    net_recv_mbps FLOAT,
    PRIMARY KEY (id)
);

-- Login attempts table
CREATE TABLE login_attempts (
    user_id INT NOT NULL,
    attempts INT DEFAULT 0,
    last_failed TIMESTAMP NULL DEFAULT NULL,
    PRIMARY KEY (user_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

INSERT INTO users (username, password, role)
VALUES ('admin', 'pbkdf2:sha256:260000$0WbCMc1zvR9JCIy5$ae02306877d84d8065c66d4644b20978d4978983d44a12f004dfa823428be018
', 'admin');