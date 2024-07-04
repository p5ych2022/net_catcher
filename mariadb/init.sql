GRANT ALL PRIVILEGES ON traffic_data.* TO 'ids'@'%' WITH GRANT OPTION;
USE traffic_data;

CREATE TABLE traffic (
    id INT AUTO_INCREMENT PRIMARY KEY,
    src_ip VARCHAR(15),
    dst_ip VARCHAR(15),
    protocol VARCHAR(10),
    payload TEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
