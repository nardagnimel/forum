package handlers

import (
	"database/sql"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"forum/email_utils"
)

// SignupHandler gère l'inscription des utilisateurs
func SignupHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Récupérer les informations de l'utilisateur à partir de la requête
		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")

		// Vérifier que toutes les informations ont été fournies
		if username == "" || email == "" || password == "" {
			http.Error(w, "Toutes les informations doivent être fournies", http.StatusBadRequest)
			return
		}

		// Vérifier que les informations de l'utilisateur sont valides
		if !IsValidUsername(username) {
			http.Error(w, "Nom d'utilisateur invalide", http.StatusBadRequest)
			return
		}
		if !email_utils.IsValidEmail(email) {
			http.Error(w, "Adresse e-mail invalide", http.StatusBadRequest)
			return
		}
		if !email_utils.IsValidPassword(password) {
			http.Error(w, "Mot de passe invalide", http.StatusBadRequest)
			return
		}

		// Hacher le mot de passe avec bcrypt
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Erreur lors du hachage du mot de passe", http.StatusInternalServerError)
			return
		}

		// Créer un nouvel utilisateur dans la base de données
		_, err = db.Exec("INSERT INTO users (username, email, password, activated) VALUES (?, ?, ?, ?)", username, email, hashedPassword, false)
		if err != nil {
			http.Error(w, "Erreur lors de la création de l'utilisateur", http.StatusInternalServerError)
			return
		}

		// Générer un jeton d'activation de compte
		token := uuid.New().String()

		// Enregistrer le jeton d'activation de compte dans la base de données
		_, err = db.Exec("INSERT INTO account_activation_tokens (user_email, token) VALUES (?, ?)", email, token)
		if err != nil {
			http.Error(w, "Erreur lors de la génération du jeton d'activation de compte", http.StatusInternalServerError)
			return
		}

		// Créer l'URL d'activation de compte
		activationURL := fmt.Sprintf("http://%s/activate-account/%s", r.Host, token)

		// Envoyer un e-mail d'activation de compte à l'utilisateur
		err = email_utils.sendAccountActivationEmail(email, activationURL)
		if err != nil {
			http.Error(w, "Erreur lors de l'envoi de l'e-mail d'activation de compte", http.StatusInternalServerError)
			return
		}

		// Afficher un message de confirmation à l'utilisateur
		fmt.Fprint(w, "Un e-mail d'activation a été envoyé à votre adresse e-mail.")
	}
}
