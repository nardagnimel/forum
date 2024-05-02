package handlers

import (
	"fmt"
	"forum/database"
	"forum/email_utils"
	"forum/models"
	"net/http"
	"net/url"
)

// UnlockAccountHandler traite la demande de déverrouillage de compte de l'utilisateur
func UnlockAccountHandler(w http.ResponseWriter, r *http.Request) {
	// Récupérer l'adresse e-mail de l'utilisateur à partir du formulaire
	email := r.FormValue("email")

	// Vérifier que l'adresse e-mail est valide
	if !email_utils.isValidEmail(email) {
		http.Error(w, "Adresse e-mail invalide", http.StatusBadRequest)
		return
	}

	// Récupérer l'utilisateur à partir de la base de données en utilisant l'adresse e-mail
	db := database.InitDB()
	var user models.User
	err := db.QueryRow("SELECT * FROM users WHERE email = ?", email).Scan(&user.ID, &user.Username, &user.Email, &user.Password, &user.Activated, &user.FailedLoginAttempts, &user.LockedUntil)
	if err != nil {
		// Si l'utilisateur n'existe pas, nous renvoyons une erreur générique pour éviter de révéler des informations sensibles
		http.Error(w, "Aucun compte associé à cette adresse e-mail", http.StatusUnauthorized)
		return
	}

	// Vérifier que le compte de l'utilisateur est verrouillé
	if user.LockedUntil.IsZero() {
		http.Error(w, "Compte non verrouillé", http.StatusBadRequest)
		return
	}

	// Réinitialiser le nombre de tentatives de connexion infructueuses de l'utilisateur et déverrouiller son compte
	err = email_utils.UnlockUserAccount(user.ID, db)
	if err != nil {
		http.Error(w, "Erreur lors du déverrouillage du compte utilisateur", http.StatusInternalServerError)
		return
	}

	// Envoyer un e-mail de confirmation de déverrouillage de compte à l'utilisateur
	unlockURL := fmt.Sprintf("http://%s/confirm-unlock-account?email=%s", r.Host, url.QueryEscape(email))
	err = email_utils.SendUnlockAccountEmail(email, unlockURL)
	if err != nil {
		http.Error(w, "Erreur lors de l'envoi de l'e-mail de confirmation de déverrouillage de compte", http.StatusInternalServerError)
		return
	}

	// Rediriger l'utilisateur vers la page de connexion avec un message de succès
	http.Redirect(w, r, "/login?unlock_account_success=true", http.StatusSeeOther)
}
