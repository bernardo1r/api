package handler

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/bernardo1r/api/database"
	"github.com/bernardo1r/api/ratelimit"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/argon2"
)

const (
	saltLen = 16

	argonTime = 3

	argonMemory = 1 << 20 //1 GiB

	argonThreads = 8

	argonOutputLen
)

const (
	registerDuration = time.Second * 10
)

const (
	apiKeyLen = 16
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

	hash := hashPassword(salt, password)

	return &credentials{
		PasswordHash: hash,
		Salt:         salt}, nil
}

func hashPassword(salt []byte, password []byte) []byte {
	hash := argon2.IDKey(password, salt, argonTime, argonMemory, argonThreads, argonOutputLen)
	return hash
}

func newUser(name string, cred *credentials) *database.User {
	return &database.User{
		Name:         name,
		Salt:         cred.Salt,
		PasswordHash: cred.PasswordHash,
		Key:          sql.NullString{},
	}
}

type Router struct {
	db      database.DB
	limiter *ratelimit.RateLimiter
}

func NewRouter(db database.DB, limiter *ratelimit.RateLimiter) *Router {
	return &Router{
		db:      db,
		limiter: limiter,
	}
}

func getIP(r *http.Request) (string, error) {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	return ip, err
}

func (router *Router) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		badRequest(w)
		return
	}
	ip, err := getIP(r)
	if err != nil {
		internalServerError(w)
		return
	}
	ok := router.limiter.LimitDuration(ip, registerDuration)
	if !ok {
		tooManyRequests(w)
		return
	}

	username, password, ok := r.BasicAuth()
	if !ok {
		basicAuthError(w)
		return
	}

	_, err = router.db.UserByName(username)
	switch {
	case err == sql.ErrNoRows:
	case err != nil:
		internalServerError(w)
		return

	default:
		http.Error(w, "User Already exists", http.StatusBadRequest)
		return
	}

	passwordDecoded, err := base64.StdEncoding.DecodeString(password)
	if err != nil {
		badRequest(w)
		return
	}

	credential, err := newCredentials(passwordDecoded)
	if err != nil {
		internalServerError(w)
		return
	}
	user := newUser(username, credential)
	err = router.db.InsertUser(user)
	if err != nil {
		internalServerError(w)
	}
}

func (router *Router) GenApiKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		badRequest(w)
		return
	}
	ip, err := getIP(r)
	if err != nil {
		internalServerError(w)
	}
	ok := router.limiter.LimitDuration(ip, registerDuration)
	if !ok {
		tooManyRequests(w)
		return
	}

	username, password, ok := r.BasicAuth()
	if !ok {
		basicAuthError(w)
		return
	}

	key := make([]byte, apiKeyLen)
	_, err = rand.Read(key)
	if err != nil {
		internalServerError(w)
		return
	}
	keyEncoded := base64.StdEncoding.EncodeToString(key)

	user, err := router.db.UserByName(username)
	switch {
	case err == sql.ErrNoRows:
		w.Write([]byte(keyEncoded))
		return

	case err != nil:
		internalServerError(w)
		return
	}

	passwordDecoded, err := base64.StdEncoding.DecodeString(password)
	if err != nil {
		badRequest(w)
		return
	}
	hash := hashPassword(user.Salt, passwordDecoded)
	if subtle.ConstantTimeCompare(hash, user.PasswordHash) != 1 {
		w.Write([]byte(keyEncoded))
		return
	}

	err = router.db.UpdateUserKeyByName(username, keyEncoded)
	if err != nil {
		internalServerError(w)
		return
	}

	w.Write([]byte(keyEncoded))
}

func (router *Router) HandleData(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		badRequest(w)
		return
	}
	ip, err := getIP(r)
	if err != nil {
		internalServerError(w)
	}

	switch {
	case r.Method == http.MethodPost:
		router.postData(w, r, ip)

	case r.Method == http.MethodGet:
		router.getData(w, r, ip)
	}
}

func (router *Router) validApiKey(w http.ResponseWriter, r *http.Request) (*database.User, bool) {
	_, apiKey, found := strings.Cut(r.Header.Get("Authorization"), "Bearer ")
	if !found {
		apiKeyError(w)
	}

	user, err := router.db.UserByKey(apiKey)
	switch {
	case err == sql.ErrNoRows:
		return nil, false

	case err != nil:
		internalServerError(w)
		return nil, false
	}
	if !user.Key.Valid {
		return nil, false
	}
	if subtle.ConstantTimeCompare([]byte(apiKey), []byte(user.Key.String)) == 0 {
		return nil, false
	}

	return &user, true
}

func (router *Router) postData(w http.ResponseWriter, r *http.Request, ip string) {
	ok := router.limiter.LimitDuration(ip, registerDuration)
	if !ok {
		tooManyRequests(w)
		return
	}
	user, ok := router.validApiKey(w, r)
	if !ok {
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		internalServerError(w)
		return
	}
	bodyFiltered := strings.ToValidUTF8(string(body), "")
	data := database.Data{
		User:    user.Name,
		Content: bodyFiltered,
	}
	err = router.db.ReplaceData(&data)
	if err != nil {
		internalServerError(w)
		return
	}
}

func (router *Router) getData(w http.ResponseWriter, r *http.Request, ip string) {
	ok := router.limiter.Limit(ip)
	if !ok {
		tooManyRequests(w)
		return
	}
	user, ok := router.validApiKey(w, r)
	if !ok {
		return
	}

	data, err := router.db.DataByUserName(user.Name)
	switch {
	case err == sql.ErrNoRows:
		return

	case err != nil:
		internalServerError(w)
		return
	}

	w.Write([]byte(data.Content))
}
