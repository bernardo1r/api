CREATE TABLE user (
    name TEXT PRIMARY KEY,
    salt BLOB NOT NULL,
    password_hash BLOB NOT NULL,
    key TEXT UNIQUE
);

CREATE TABLE data (
    user TEXT PRIMARY KEY,
    content TEXT NOT NULL,
    FOREIGN KEY (user)
        REFERENCES user (name)
);