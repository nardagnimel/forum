package handlers

import (
	"forum/database"
	"forum/email_utils"
	"forum/models"
	"net/http"
	"time"
)

// VerifyEmailTokenHandler traite la demande de vérification de compte de l'utilisateur en utilisant le jeton de vérification de compte
func VerifyEmailTokenHandler(w http.ResponseWriter, r *http.Request) {
	// Récupérer le jeton de vérification de compte à partir de l'URL
	token := r.URL.Query().Get("token")

	// Vérifier que le jeton de vérification de compte est valide
	db := database.InitDB()
	var emailVerificationToken models.EmailVerificationToken
	err := db.QueryRow("SELECT * FROM email_verification_tokens WHERE token = ?", token).Scan(&emailVerificationToken.ID, &emailVerificationToken.UserID, &emailVerificationToken.Token, &emailVerificationToken.CreatedAt)
	if err != nil {
		// Si le jeton de vérification de compte n'existe pas, nous renvoyons une erreur générique pour éviter de révéler des informations sensibles
		http.Error(w, "Jeton de vérification de compte invalide ou expiré", http.StatusBadRequest)
		return
	}

	// Vérifier que le jeton de vérification de compte n'a pas expiré
	if time.Since(emailVerificationToken.CreatedAt) > time.Hour*24 {
		http.Error(w, "Jeton de vérification de compte expiré", http.StatusBadRequest)
		return
	}

	// Récupérer l'utilisateur à partir de la base de données en utilisant l'ID du jeton de vérification de compte
	var user models.User
	err = db.QueryRow("SELECT * FROM users WHERE id = ?", emailVerificationToken.UserID).Scan(&user.ID, &user.Username, &user.Email, &user.Password, &user.Activated, &user.FailedLoginAttempts, &user.LockedUntil)
	if err != nil {
		// Si l'utilisateur n'existe pas, nous renvoyons une erreur générique pour éviter de révéler des informations sensibles
		http.Error(w, "Aucun compte associé à ce jeton de vérification de compte", http.StatusUnauthorized)
		return
	}

	err = email_utils.ActivateUserAccount(token, db)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
}
