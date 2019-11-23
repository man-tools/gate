CREATE TABLE IF NOT EXISTS rbac_user (
	id INT UNSIGNED NOT NULL PRIMARY KEY AUTO_INCREMENT,
	username VARCHAR(100) NOT NULL,
	email VARCHAR(100) NOT NULL,
	password VARCHAR(100) NOT NULL,
	active TINYINT NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS rbac_permission (
	id INT UNSIGNED NOT NULL PRIMARY KEY AUTO_INCREMENT,
	name VARCHAR(40) NOT NULL,
	method VARCHAR(10) NOT NULL,
	route VARCHAR(100) NOT NULL,
	description TEXT,

	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS rbac_role (
	id INT UNSIGNED NOT NULL PRIMARY KEY AUTO_INCREMENT,
	name VARCHAR(40) NOT NULL,
	description TEXT,

	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS rbac_role_permission (
	id INT UNSIGNED NOT NULL PRIMARY KEY AUTO_INCREMENT,
	role_id INT UNSIGNED NOT NULL,
	permission_id INT UNSIGNED NOT NULL,

	FOREIGN KEY (role_id) REFERENCES rbac_role(id) ON DELETE CASCADE,
	FOREIGN KEY (permission_id) REFERENCES rbac_permission(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS rbac_user_role (
	id INT UNSIGNED NOT NULL PRIMARY KEY AUTO_INCREMENT,
	role_id INT UNSIGNED NOT NULL,
	user_id INT UNSIGNED NOT NULL,

	FOREIGN KEY (role_id) REFERENCES rbac_role(id) ON DELETE CASCADE,
	FOREIGN KEY (user_id) REFERENCES rbac_user(id) ON DELETE CASCADE
);