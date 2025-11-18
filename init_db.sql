USE nas_web;

-- 1. Create Tables
CREATE TABLE IF NOT EXISTS `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `password` varchar(255) NOT NULL,
  `role` enum('admin','user') DEFAULT 'user',
  `quota_gb` int DEFAULT '20',
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
);

CREATE TABLE IF NOT EXISTS `folders` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `name` varchar(255) NOT NULL,
  `parent_id` int DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `parent_id` (`parent_id`),
  KEY `user_id_fk` (`user_id`),
  CONSTRAINT `folders_user_fk` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  CONSTRAINT `folders_ibfk_1` FOREIGN KEY (`parent_id`) REFERENCES `folders` (`id`) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS `files` (
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
  CONSTRAINT `files_user_fk` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  CONSTRAINT `files_ibfk_1` FOREIGN KEY (`folder_id`) REFERENCES `folders` (`id`) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS `system_stats` (
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

CREATE TABLE IF NOT EXISTS `alerts` (
  `id` int NOT NULL AUTO_INCREMENT,
  `timestamp` datetime DEFAULT CURRENT_TIMESTAMP,
  `level` varchar(20) NOT NULL,
  `message` text NOT NULL,
  `is_read` tinyint(1) DEFAULT '0',
  PRIMARY KEY (`id`)
);

CREATE TABLE IF NOT EXISTS `login_attempts` (
    `user_id` INT NOT NULL,
    `attempts` INT DEFAULT 0,
    `last_failed` TIMESTAMP NULL DEFAULT NULL,
    PRIMARY KEY (`user_id`),
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
);

-- 2. Create the default Admin User
-- This user (admin/password) MUST be changed after first login.
INSERT INTO users (username, password, role)
VALUES ('admin', 'pbkdf2:sha256:260000$EXLF0dhv2EdIsrj0$9a7c478f6bd3e59546ac23af925950050672cfc024bb0f986546d6c0412fefed', 'admin');


-- Configuration Backup
CREATE TABLE IF NOT EXISTS app_config (
    config_key VARCHAR(100) PRIMARY KEY,
    config_value TEXT NOT NULL
);

INSERT INTO app_config (config_key, config_value)
VALUES ('backup_frequency_minutes', '1')
ON DUPLICATE KEY UPDATE config_value = VALUES(config_value);