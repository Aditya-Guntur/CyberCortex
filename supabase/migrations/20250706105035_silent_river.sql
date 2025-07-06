-- Create vulnerable database schema
CREATE DATABASE IF NOT EXISTS vulnerable_db;
USE vulnerable_db;

-- Create users table with weak password hashing
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(32) NOT NULL, -- MD5 hashes (weak)
    email VARCHAR(100) NOT NULL,
    is_admin BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert some test users with weak passwords
INSERT INTO users (username, password, email, is_admin) VALUES
('admin', MD5('admin123'), 'admin@example.com', TRUE),
('user1', MD5('password123'), 'user1@example.com', FALSE),
('user2', MD5('qwerty'), 'user2@example.com', FALSE);

-- Create a table with sensitive data
CREATE TABLE customer_data (
    id INT AUTO_INCREMENT PRIMARY KEY,
    customer_name VARCHAR(100) NOT NULL,
    credit_card VARCHAR(16) NOT NULL, -- Unencrypted credit card numbers
    ssn VARCHAR(11) NOT NULL, -- Unencrypted SSNs
    address VARCHAR(200) NOT NULL,
    phone VARCHAR(20) NOT NULL
);

-- Insert some fake sensitive data
INSERT INTO customer_data (customer_name, credit_card, ssn, address, phone) VALUES
('John Doe', '4111111111111111', '123-45-6789', '123 Main St, Anytown, USA', '555-123-4567'),
('Jane Smith', '5555555555554444', '987-65-4321', '456 Oak Ave, Somewhere, USA', '555-987-6543'),
('Bob Johnson', '378282246310005', '456-78-9012', '789 Pine Rd, Nowhere, USA', '555-456-7890');

-- Create a vulnerable stored procedure with SQL injection
DELIMITER //
CREATE PROCEDURE get_user_by_username(IN username_param VARCHAR(50))
BEGIN
    SET @query = CONCAT('SELECT * FROM users WHERE username = ''', username_param, '''');
    PREPARE stmt FROM @query;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
END //
DELIMITER ;

-- Create a user with excessive privileges
CREATE USER 'dbuser'@'%' IDENTIFIED BY 'dbpassword';
GRANT ALL PRIVILEGES ON *.* TO 'dbuser'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;

-- Create a table for storing logs (with SQL injection vulnerability)
CREATE TABLE logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    action VARCHAR(100) NOT NULL,
    user_id INT,
    details TEXT,
    ip_address VARCHAR(15),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create a vulnerable function for logging
DELIMITER //
CREATE FUNCTION log_action(action_param VARCHAR(100), user_id_param INT, details_param TEXT, ip_param VARCHAR(15))
RETURNS INT
DETERMINISTIC
BEGIN
    SET @query = CONCAT('INSERT INTO logs (action, user_id, details, ip_address) VALUES (''', 
                        action_param, ''', ', user_id_param, ', ''', details_param, ''', ''', ip_param, ''')');
    PREPARE stmt FROM @query;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
    
    RETURN LAST_INSERT_ID();
END //
DELIMITER ;