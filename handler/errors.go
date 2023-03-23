package handler

import "net/http"

func internalServerError(w http.ResponseWriter) {
	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
}

func badRequest(w http.ResponseWriter) {
	http.Error(w, "Bad Request", http.StatusBadRequest)
}

func tooManyRequests(w http.ResponseWriter) {
	http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
}

func basicAuthError(w http.ResponseWriter) {
	http.Error(w, "Malformed Authorization header: expected basic auth", http.StatusBadRequest)
}
