package handlers

import (
	"net/http"

	"forum/database"
	"forum/models"

	"github.com/gorilla/mux"
)

// ActivateAccountHandler traite la demande d'activation de compte
func ActivateAccountHandler(w http.ResponseWriter, r *http.Request) {
	// Récupérer le jeton d'activation de compte à partir de l'URL
	token := mux.Vars(r)["token"]
	if token == "" {
		http.Error(w, "Jeton d'activation de compte requis", http.StatusBadRequest)
		return
	}

	// Vérifier que le jeton d'activation de compte est valide
	activationToken, err := models.GetValidAccountActivationToken(token)
	if err != nil {
		http.Error(w, "Jeton d'activation de compte invalide ou expiré", http.StatusBadRequest)
		return
	}

	// Activer le compte utilisateur dans la base de données
	db := database.InitDB()
	result, err := db.Exec("UPDATE users SET activated = ? WHERE email = ?", true, activationToken.UserEmail)
	if err != nil {
		http.Error(w, "Erreur lors de l'activation du compte utilisateur", http.StatusInternalServerError)
		return
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		http.Error(w, "Erreur lors de la vérification du nombre de lignes affectées", http.StatusInternalServerError)
		return
	}
	if rowsAffected == 0 {
		http.Error(w, "Aucun compte utilisateur trouvé pour le jeton d'activation", http.StatusNotFound)
		return
	}

	// Supprimer le jeton d'activation de compte de la base de données
	_, err = db.Exec("DELETE FROM account_activation_tokens WHERE token = ?", token)
	if err != nil {
		http.Error(w, "Erreur lors de la suppression du jeton d'activation de compte", http.StatusInternalServerError)
		return
	}

	// Rediriger l'utilisateur vers la page de connexion avec un message de succès
	http.Redirect(w, r, "/login?account_activated=true", http.StatusSeeOther)
}
