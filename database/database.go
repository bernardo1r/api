package database

import "database/sql"

type DB struct {
	*sql.DB
}

type User struct {
	Name         string
	Salt         []byte
	PasswordHash []byte
	Key          sql.NullString
}

type Data struct {
	User    string
	Content string
}

func New(filepath string) (DB, error) {
	pool, err := sql.Open("sqlite3", filepath)
	if err != nil {
		return DB{}, err
	}
	return DB{pool}, nil
}

func (db *DB) InsertUser(user *User) error {
	_, err := db.Exec(
		`INSERT INTO user 
		 VALUES (?, ?, ?, ?)`,
		user.Name,
		user.Salt,
		user.PasswordHash,
		user.Key,
	)
	return err
}

func (db *DB) UpdateUserKeyByName(name string, key string) error {
	_, err := db.Exec(
		`UPDATE user 
		 SET key = ? 
		 WHERE name = ?`,
		key,
		name,
	)
	return err
}

func (db *DB) userQueryRow(query string, arg string) (User, error) {
	var user User
	err := db.QueryRow(query, arg).Scan(
		&user.Name,
		&user.Salt,
		&user.PasswordHash,
		&user.Key,
	)
	return user, err
}

func (db *DB) UserByName(name string) (User, error) {
	user, err := db.userQueryRow(
		`SELECT * 
		 FROM user 
		 WHERE name = ?`,
		name,
	)
	if err != nil {
		return User{}, err
	}
	return user, nil
}

func (db *DB) UserByKey(key string) (User, error) {
	user, err := db.userQueryRow(
		`SELECT * 
		 FROM user
		 WHERE key = ?`,
		key,
	)
	if err != nil {
		return User{}, err
	}
	return user, nil
}

func (db *DB) dataQueryRow(query string, arg string) (*Data, error) {
	var data Data
	err := db.QueryRow(query, arg).Scan(
		&data.User,
		&data.Content,
	)
	return &data, err
}

func (db *DB) DataByUserName(name string) (*Data, error) {
	data, err := db.dataQueryRow(
		`SELECT *
		 FROM data
		 WHERE user = ?`,
		name,
	)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (db *DB) ReplaceData(data *Data) error {
	_, err := db.Exec(
		`REPLACE INTO data
		 VALUES (?, ?)`,
		data.User,
		data.Content,
	)
	return err
}
