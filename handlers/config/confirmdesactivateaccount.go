package handlers

import (
	"forum/database"
	"forum/email_utils"
	"forum/models"
	"net/http"
)

// DeactivateAccountHandler traite la demande de désactivation de compte de l'utilisateur
func ConfirmDesactivateAccountHandler(w http.ResponseWriter, r *http.Request) {
	// Vérifier que la demande est de type POST
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	// Vérifier que l'utilisateur est authentifié
	userID := email_utils.GetUserID(r)
	if userID == 0 {
		http.Error(w, "Vous devez être connecté pour désactiver votre compte", http.StatusUnauthorized)
		return
	}

	// Récupérer l'adresse e-mail de l'utilisateur à partir de la base de données
	db := database.InitDB()
	var user models.User
	err := db.QueryRow("SELECT * FROM users WHERE id = ?", userID).Scan(&user.ID, &user.Username, &user.Email, &user.Password, &user.Activated, &user.FailedLoginAttempts, &user.LockedUntil)
	if err != nil {
		// Si l'utilisateur n'existe pas, nous renvoyons une erreur générique pour éviter de révéler des informations sensibles
		http.Error(w, "Erreur lors de la récupération des informations de l'utilisateur", http.StatusInternalServerError)
		return
	}

	// Désactiver le compte de l'utilisateur dans la base de données
	err = models.DesactivateUserAndDeleteAssociatedTokens(userID, db)
	if err != nil {
		http.Error(w, "Erreur lors de la désactivation du compte utilisateur", http.StatusInternalServerError)
		return
	}

}
