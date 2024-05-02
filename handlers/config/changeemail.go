package handlers

import (
	"fmt"
	"forum/database"
	"forum/email_utils"
	"forum/models"
	"net/http"
	"net/url"

	"github.com/google/uuid"
)

// ChangeEmailHandler traite la demande de changement d'adresse e-mail de l'utilisateur
func ChangeEmailHandler(w http.ResponseWriter, r *http.Request) {
	// Vérifier que l'utilisateur est authentifié
	userID := email_utils.GetUserID(r)
	if userID == 0 {
		http.Error(w, "Vous devez être connecté pour changer votre adresse e-mail", http.StatusUnauthorized)
		return
	}

	// Récupérer l'adresse e-mail actuelle de l'utilisateur à partir de la base de données
	db := database.InitDB()
	var user models.User
	err := db.QueryRow("SELECT * FROM users WHERE id = ?", userID).Scan(&user.ID, &user.Username, &user.Email, &user.Password, &user.Activated, &user.FailedLoginAttempts, &user.LockedUntil)
	if err != nil {
		http.Error(w, "Erreur lors de la récupération des informations de l'utilisateur", http.StatusInternalServerError)
		return
	}

	// Récupérer la nouvelle adresse e-mail à partir du formulaire
	newEmail := r.FormValue("new_email")

	// Vérifier que la nouvelle adresse e-mail est valide et non utilisée
	valid, err := email_utils.isValidNewEmail(newEmail)
	if err != nil {
		http.Error(w, "Erreur lors de la vérification de la nouvelle adresse e-mail", http.StatusInternalServerError)
		return
	}
	if !valid {
		http.Error(w, "Cette adresse e-mail est déjà utilisée", http.StatusBadRequest)
		return
	}

	// Générer un nouveau jeton de vérification de compte pour la nouvelle adresse e-mail
	token := email_utils.GenerateEmailVerificationToken()

	// Mettre à jour l'adresse e-mail de l'utilisateur dans la base de données
	db.Exec("UPDATE users SET email = ? WHERE id = ?", newEmail, userID)

	// Supprimer tous les jetons de vérification de compte associés à l'ancienne adresse e-mail
	db.Exec("DELETE FROM email_verification_tokens WHERE user_id = ?", userID)

	// Générer un nouveau jeton de vérification de compte pour la nouvelle adresse e-mail
	token = uuid.New().String()
	db.Exec("INSERT INTO email_verification_tokens (user_id, token) VALUES (?, ?)", userID, token)

	// Envoyer un e-mail de vérification de compte à la nouvelle adresse e-mail
	verifyURL := fmt.Sprintf("http://%s/verify-email?token=%s", r.Host, url.QueryEscape(token))
	email_utils.SendVerifyEmailEmail(newEmail, verifyURL)

	if err != nil {
		http.Error(w, "Erreur lors de l'envoi de l'e-mail de vérification de compte", http.StatusInternalServerError)
		return
	}

	// Rediriger l'utilisateur vers la page de connexion avec un message de succès
	http.Redirect(w, r, "/login?change_email_success=true", http.StatusSeeOther)
}
