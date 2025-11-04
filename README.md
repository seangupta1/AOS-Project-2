# AOS-Project-2

## Project Setup

After running `sudo docker-compose up --build` for the first time, you must manually initialize the database.

1.  Open a second terminal.
2.  Find your database container ID: `sudo docker ps`
3.  Connect to the MySQL server:
    `sudo docker exec -it <your-db-container-name> mysql -u nas_user -p`
    (Password is `supersecretpassword`)
4.  Run the following SQL commands to create the tables and the default admin user:

```sql
USE nas_web;

CREATE TABLE `users` (
`id` int NOT NULL AUTO_INCREMENT,
`username` varchar(50) NOT NULL,
`password` varchar(255) NOT NULL,
`role` enum('admin','user') DEFAULT 'user',
PRIMARY KEY (`id`),
UNIQUE KEY `username` (`username`)
);

CREATE TABLE folders ( id int NOT NULL AUTO_INCREMENT, user_id int NOT NULL, name varchar(255) NOT NULL, parent_id int DEFAULT NULL, created_at timestamp NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (id), KEY parent_id (parent_id), CONSTRAINT folders_ibfk_1 FOREIGN KEY (parent_id) REFERENCES folders (id) );

CREATE TABLE files ( id int NOT NULL AUTO_INCREMENT, user_id int NOT NULL, folder_id int DEFAULT NULL, original_name varchar(255) NOT NULL, mime_type varchar(100) DEFAULT NULL, size bigint DEFAULT NULL, uploaded_at timestamp NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (id), KEY folder_id (folder_id), CONSTRAINT files_ibfk_1 FOREIGN KEY (folder_id) REFERENCES folders (id) );

CREATE TABLE system_stats (
    id INT NOT NULL AUTO_INCREMENT,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    cpu_percent FLOAT,
    mem_percent FLOAT,
    net_sent_mbps FLOAT,
    net_recv_mbps FLOAT,
    PRIMARY KEY (id)
);

INSERT INTO users (username, password, role) VALUES ('admin', 'admin', 'admin');
