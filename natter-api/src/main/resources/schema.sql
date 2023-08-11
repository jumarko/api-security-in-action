
CREATE TABLE  spaces(
    space_id INT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    owner VARCHAR(30) NOT NULL
);

CREATE SEQUENCE space_id_seq;

CREATE TABLE  messages(
    space_id INT NOT NULL REFERENCES spaces(space_id),
    msg_id INT PRIMARY KEY,
    author VARCHAR(30) NOT NULL,
    msg_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    msg_text VARCHAR(1024) NOT NULL
);

CREATE SEQUENCE msg_id_seq;

CREATE INDEX msg_timestamp_idx ON messages(msg_time);

CREATE UNIQUE INDEX space_name_idx ON spaces(name);

CREATE USER natter_api_user PASSWORD 'password';
GRANT SELECT, INSERT ON spaces, messages TO natter_api_user;
GRANT DELETE ON messages TO natter_api_user;

CREATE TABLE users(
    user_id VARCHAR(30) PRIMARY KEY,
    pw_hash VARCHAR(255) NOT NULL
);
GRANT SELECT, INSERT On users TO natter_api_user;

CREATE TABLE audit_log(
    audit_id INT NULL,
    method VARCHAR(10) NOT NULL,
    path VARCHAR(100) NOT NULL,
    user_id VARCHAR(30) NULL,
    status INT NULL,
    audit_time TIMESTAMP NOT NULL
);
CREATE SEQUENCE audit_id_seq;
GRANT SELECT, INSERT ON audit_log TO natter_api_user;

CREATE TABLE permissions(
    space_id INT NOT NULL REFERENCES spaces(space_id),
    user_id VARCHAR(30) NOT NULL REFERENCES users(user_id),
    -- perms are: 'r' for "read", 'w' for "write", 'd' for "delete"
    perms VARCHAR(3) NOT NULL,
    PRIMARY KEY (space_id, user_id)
);
GRANT SELECT, INSERT ON permissions TO natter_api_user;

CREATE TABLE tokens(
    token_id VARCHAR(100) PRIMARY KEY,
    user_id VARCHAR(30) NOT NULL,
    expiry TIMESTAMP  NOT NULL,
    -- attributes are a JSON text
    attributes VARCHAR(4096) NOT NULL
);
GRANT SELECT, INSERT, DELETE ON tokens TO natter_api_user;

-- to make sure regular cleanup of old tokens can be fast
CREATE INDEX expired_token_idx ON tokens(expiry);

-- Ch8 (p. 269/270) - adding groups of users
-- NOTE: I added another table 'groups' to make groups more explicit and decoupled
CREATE TABLE groups(
    group_id VARCHAR(30) PRIMARY KEY
);
CREATE TABLE group_members(
    group_id VARCHAR(30) NOT NULL REFERENCES groups(group_id),
    user_id VARCHAR(30) NOT NULL REFERENCES users(user_id));
CREATE INDEX group_member_user_idx ON group_members(user_id);
CREATE TABLE user_permissions(
    space_id INT NOT NULL REFERENCES spaces(space_id),
    user_id VARCHAR(30) NOT NULL REFERENCES users(user_id),
    -- perms are: 'r' for "read", 'w' for "write", 'd' for "delete"
    perms VARCHAR(3) NOT NULL,
    PRIMARY KEY (space_id, user_id)
);
GRANT SELECT, INSERT ON user_permissions TO natter_api_user;

CREATE TABLE group_permissions(
    space_id INT NOT NULL REFERENCES spaces(space_id),
    group_id VARCHAR(30) NOT NULL REFERENCES groups(group_id),
    -- perms are: 'r' for "read", 'w' for "write", 'd' for "delete"
    perms VARCHAR(3) NOT NULL,
    PRIMARY KEY (space_id, group_id)
);
GRANT SELECT, INSERT ON group_permissions TO natter_api_user;

-- first, I need to rename the existing permissions table ...
ALTER TABLE permissions RENAME TO permissions_old;
-- ... then I can create a new 'permissions' view
CREATE VIEW permissions(space_id, user_or_group_id, perms) AS
    SELECT space_id, user_id, perms FROM user_permissions
    UNION ALL
    SELECT space_id, group_id, perms FROM group_permissions;
GRANT SELECT ON permissions TO natter_api_user;