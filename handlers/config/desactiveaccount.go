package handlers

import (
	"forum/email_utils"
	"net/http"
	"text/template"
)

// DeactivateAccountHandler traite la demande de désactivation de compte de l'utilisateur
func DeactivateAccountHandler(w http.ResponseWriter, r *http.Request) {
	// Vérifier que l'utilisateur est authentifié
	userID := email_utils.GetUserID(r)
	if userID == 0 {
		http.Error(w, "Vous devez être connecté pour désactiver votre compte", http.StatusUnauthorized)
		return
	}

	// Afficher la page de confirmation de désactivation de compte
	tmpl := template.Must(template.ParseFiles("templates/confirm-deactivate-account.html"))
	tmpl.Execute(w, nil)
}
