package handlers

import (
	"forum/email_utils"
	"forum/models"
	"net/http"
)

// ConfirmDeleteAccountHandler traite la demande de confirmation de suppression de compte de l'utilisateur
func ConfirmDeleteAccountHandler(w http.ResponseWriter, r *http.Request) {
	// Vérifier que l'utilisateur est authentifié
	userID := email_utils.GetUserID(r)
	if userID == 0 {
		http.Error(w, "Vous devez être connecté pour supprimer votre compte", http.StatusUnauthorized)
		return
	}

	// Supprimer le compte de l'utilisateur dans la base de données
	err := models.DeleteUserAndAssociatedTokens(userID, db)
	if err != nil {
		http.Error(w, "Erreur lors de la suppression du compte utilisateur", http.StatusInternalServerError)
		return
	}

}
