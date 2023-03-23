package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/bernardo1r/api/database"
	"github.com/bernardo1r/api/handler"
	"github.com/bernardo1r/api/ratelimit"
)

func checkError(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}

func main() {
	db, err := database.New("db.db")
	checkError(err)
	limiter := ratelimit.New()
	router := handler.NewRouter(db, limiter)

	mux := http.NewServeMux()
	mux.HandleFunc("/register", router.Register)
	mux.HandleFunc("/key", router.GenApiKey)

	fmt.Println("Listening in http://localhost:54321")
	err = http.ListenAndServe("localhost:54321", mux)
	checkError(err)
}
