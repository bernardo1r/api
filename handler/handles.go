package handler

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"

	"golang.org/x/crypto/argon2"
)

const (
	saltLen = 16

	argonTime = 3

	argonMemory = 1 << 20 //1 GiB

	argonThreads = 8

	argonOutputLen
)

type credentials struct {
	PasswordHash []byte
	Salt         []byte
}

func newCredentials(password []byte) (*credentials, error) {
	salt := make([]byte, saltLen)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, fmt.Errorf("credentials creation error: salt creation: %w", err)
	}

	hash := argon2.IDKey(password, salt, argonTime, argonMemory, argonThreads, argonOutputLen)

	return &credentials{
		PasswordHash: hash,
		Salt:         salt}, nil
}

type Database struct {
	User  map[string]*credentials
	Token map[string]string
	Data  map[string]string
}

func NewDatabase() Database {
	return Database{
		User:  make(map[string]*credentials),
		Token: make(map[string]string),
		Data:  make(map[string]string)}
}

func (db *Database) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	username, password, ok := r.BasicAuth()
	if !ok {
		http.Error(w, "Malformed Authorization header: expected basic auth", http.StatusBadRequest)
		return
	}

	if _, ok = db.User[username]; ok {
		http.Error(w, "User Already exists", http.StatusBadRequest)
		return
	}

	passwordDecoded, err := base64.StdEncoding.DecodeString(password)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	credential, err := newCredentials(passwordDecoded)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	db.User[username] = credential
}
