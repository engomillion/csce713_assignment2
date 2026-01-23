-- Initialize the user database for the network security assignment
-- This database contains flags and sensitive data that will be transmitted
-- over an UNENCRYPTED connection (MITM vulnerability)

CREATE DATABASE IF NOT EXISTS userdb;
USE userdb;

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL,
    role VARCHAR(20) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert sample users
INSERT INTO users (username, email, role) VALUES
    ('alice', 'alice@example.com', 'admin'),
    ('bob', 'bob@example.com', 'user'),
    ('charlie', 'charlie@example.com', 'developer'),
    ('diana', 'diana@example.com', 'user'),
    ('eve', 'eve@example.com', 'user');

-- Secrets table (contains FLAG 1 - the API token)
CREATE TABLE IF NOT EXISTS secrets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    secret_name VARCHAR(100) NOT NULL,
    secret_value TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- FLAG 1: This will be transmitted in PLAINTEXT when queried
-- This flag also serves as the API token for the secret_api service (port 8888)
INSERT INTO secrets (secret_name, secret_value, description) VALUES
    ('api_token', 
     'FLAG{n3tw0rk_tr4ff1c_1s_n0t_s3cur3}',
     'API authentication token for secret services - MITM attack will reveal this!');

-- Additional secret data to make it realistic
INSERT INTO secrets (secret_name, secret_value, description) VALUES
    ('database_backup_key', 
     'backup_key_7h1s_1s_n0t_4_fl4g',
     'Encryption key for database backups'),
    ('admin_recovery_code',
     'recovery_c0d3_4lso_n0t_4_fl4g',
     'Recovery code for admin account');

-- Create a view for easier querying
CREATE VIEW user_summary AS
SELECT id, username, email, role
FROM users;

-- Grant necessary permissions (already root, but for completeness)
GRANT ALL PRIVILEGES ON userdb.* TO 'root'@'%';
FLUSH PRIVILEGES;

-- Display initialization complete message
SELECT 'Database initialized successfully!' AS status;
SELECT 'WARNING: SSL/TLS is DISABLED - All traffic is UNENCRYPTED!' AS security_warning;
