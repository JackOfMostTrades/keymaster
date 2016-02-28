DROP TABLE IF EXISTS `client`;
CREATE TABLE `client` (
  `id` INTEGER PRIMARY KEY,
  `external_id` varchar(255) NOT NULL UNIQUE
);
DROP TABLE IF EXISTS `audit_log`;
CREATE TABLE `audit_log` (
  `id` INTEGER PRIMARY KEY,
  `client_id` int(10) NOT NULL,
  `description` varchar(1023) NOT NULL,
  `log_time` datetime NOT NULL,
  FOREIGN KEY (client_id) REFERENCES client(id)
);
DROP TABLE IF EXISTS `client_cert`;
CREATE TABLE `client_cert` (
  `id` INTEGER PRIMARY KEY,
  `client_id` int(10) NOT NULL,
  `certificate` mediumblob NOT NULL,
  `signature` varchar(1023) NOT NULL,
  `valid_from` datetime NOT NULL,
  `valid_until` datetime NOT NULL,
  FOREIGN KEY (client_id) REFERENCES client(id)
);
CREATE INDEX `client_cert_valid_until_idx` ON `client_cert` (`valid_until`);
CREATE INDEX `client_cert_signature_idx` ON `client_cert` (`signature`);
DROP TABLE IF EXISTS `client_perm`;
CREATE TABLE `client_perm` (
  `client_id` int(10) NOT NULL,
  `secret_key` varchar(255) NOT NULL,
  `can_read` tinyint(1) NOT NULL,
  `can_write` tinyint(1) NOT NULL,
  FOREIGN KEY (client_id) REFERENCES client(id)
);
DROP TABLE IF EXISTS `secret`;
CREATE TABLE `secret` (
  `id` INTEGER PRIMARY KEY,
  `client_cert_id` int(10) NOT NULL,
  `secret_key` varchar(255) NOT NULL,
  `valid_from` datetime NOT NULL,
  `valid_until` datetime NOT NULL,
  `secret` mediumblob NOT NULL,
  FOREIGN KEY (client_cert_id) REFERENCES client_cert(id)
);
CREATE INDEX `secret_secret_key_idx` ON `secret` (`secret_key`);
CREATE INDEX `secret_valid_until_idx` ON `secret` (`valid_until`);
