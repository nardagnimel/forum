package handlers

import (
	"database/sql"
	"fmt"
	"forum/database"
	"forum/models"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// ResetPasswordRequestHandler affiche le formulaire de demande de réinitialisation de mot de passe
func ResetPasswordRequestHandler(w http.ResponseWriter, r *http.Request) {
	// Récupérer l'adresse e-mail à partir du formulaire
	email := r.FormValue("email")

	// Récupérer l'utilisateur à partir de la base de données en utilisant l'adresse e-mail
	db := database.InitDB()
	var user models.User
	err := db.QueryRow("SELECT * FROM users WHERE email = ?", email).Scan(&user.ID, &user.Username, &user.Email, &user.Password, &user.Activated, &user.FailedLoginAttempts, &user.LockedUntil)
	if err == sql.ErrNoRows {
		http.Error(w, "Aucun compte associé à cette adresse e-mail", http.StatusUnauthorized)
		return
	} else if err != nil {
		http.Error(w, "Erreur lors de la récupération de l'utilisateur dans la base de données", http.StatusInternalServerError)
		return
	}

	// Générer un jeton de réinitialisation de mot de passe avec une durée de vie d'une heure
	token := uuid.New().String()
	expiration := time.Now().Add(time.Hour)
	_, err = db.Exec("INSERT INTO password_reset_tokens (user_id, token, expiration) VALUES (?, ?, ?)", user.ID, token, expiration)
	if err != nil {
		http.Error(w, "Erreur lors de la génération du jeton de réinitialisation de mot de passe", http.StatusInternalServerError)
		return
	}

	// Créer l'URL de réinitialisation de mot de passe
	resetURL := fmt.Sprintf("http://%s/reset-password/%s", r.Host, token)

	// Envoyer un e-mail de réinitialisation de mot de passe à l'utilisateur
	err = email_utils.sendPasswordResetEmail(user.Email, resetURL)
	if err != nil {
		http.Error(w, "Erreur lors de l'envoi de l'e-mail de réinitialisation de mot de passe", http.StatusInternalServerError)
		return
	}

	// Rediriger l'utilisateur vers la page de connexion avec un message de succès
	http.Redirect(w, r, "/login?reset_password_request_sent=true", http.StatusSeeOther)
}
