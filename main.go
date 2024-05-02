package main

import (
	"forum/handlers"
	"forum/middleware"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
	// Créer un nouveau routeur
	r := mux.NewRouter()

	// Définir les routes publiques
	r.HandleFunc("/", HomeHandler).Methods("GET")
	r.HandleFunc("/login", handlers.LoginHandler).Methods("GET", "POST")
	r.HandleFunc("/signup", handlers.SignupHandler).Methods("GET", "POST")

	// Définir les routes protégées
	r.HandleFunc("/profile", middleware.RequireAuth(ProfileHandler)).Methods("GET")
	r.HandleFunc("/logout", middleware.RequireAuth(LogoutHandler)).Methods("POST")

	// Démarrer le serveur HTTP
	http.ListenAndServe(":8080", r)
}
