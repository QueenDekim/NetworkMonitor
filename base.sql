CREATE DATABASE network_monitoring;
USE network_monitoring;

CREATE TABLE scans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip VARCHAR(15),
    status VARCHAR(10),
    device_info JSON,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);