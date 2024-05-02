package handlers

import (
	"forum/database"
	"forum/email_utils"
	"forum/models"
	"net/http"
)

// VerifyEmailHandler traite la demande de vérification de compte de l'utilisateur
func VerifyEmailHandler(w http.ResponseWriter, r *http.Request) {
	// Récupérer l'adresse e-mail de l'utilisateur à partir du formulaire
	email := r.FormValue("email")

	// Vérifier que l'adresse e-mail est valide
	if !email_utils.IsValidEmail(email) {
		http.Error(w, "Adresse e-mail invalide", http.StatusUnauthorized)

		// Récupérer l'utilisateur à partir de la base de données en utilisant l'adresse e-mail
		db := database.InitDB()
		var user models.User
		err := db.QueryRow("SELECT * FROM users WHERE email = ?", email).Scan(&user.ID, &user.Username, &user.Email, &user.Password, &user.Activated, &user.FailedLoginAttempts, &user.LockedUntil)
		if err != nil {
			// Si l'utilisateur n'existe pas, nous renvoyons une erreur générique pour éviter de révéler des informations sensibles
			http.Error(w, "Aucun compte associé à cette adresse e-mail", http.StatusUnauthorized)
			return
		}

		// Vérifier que le compte de l'utilisateur n'est pas déjà activé
		if user.Activated {
			http.Error(w, "Ce compte est déjà activé", http.StatusBadRequest)
			return
		}

		//vérification de compte et d'envoi de l'e-mail de vérification
		err = email_utils.sendVerifyEmail(user.Email, user.ID, db)
		if err != nil {
			http.Error(w, "Erreur lors de l'envoi de l'e-mail de vérification de compte", http.StatusInternalServerError)
			return
		}

		// Rediriger l'utilisateur vers la page de connexion avec un message de succès
		http.Redirect(w, r, "/login?verify_email_request_success=true", http.StatusSeeOther)
	}
}
