package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/bernardo1r/api/handler"
)

func main() {
	db := handler.NewDatabase()
	mux := http.NewServeMux()
	mux.HandleFunc("/register", db.Register)
	fmt.Println("Listening in http://localhost:54321")
	err := http.ListenAndServe("localhost:54321", mux)
	if err != nil {
		log.Fatalln(err)
	}
}
