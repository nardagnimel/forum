package handlers

import (
	"forum/database"
	"forum/models"
	"html/template"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

// ResetPasswordFormHandler affiche le formulaire de réinitialisation de mot de passe
func ResetPasswordFormHandler(w http.ResponseWriter, r *http.Request) {
	// Récupérer le jeton de réinitialisation de mot de passe à partir de l'URL
	token := mux.Vars(r)["token"]

	// Vérifier que le jeton de réinitialisation de mot de passe est valide
	resetToken, err := getValidPasswordResetToken(token)
	if err != nil {
		http.Error(w, "Jeton de réinitialisation de mot de passe invalide ou expiré", http.StatusBadRequest)
		return
	}

	// Vérifier que le jeton de réinitialisation de mot de passe n'a pas expiré
	if time.Since(resetToken.CreatedAt) > time.Hour*24 {
		http.Error(w, "Jeton de réinitialisation de mot de passe expiré", http.StatusUnauthorized)
		return
	}

	// Afficher le formulaire de réinitialisation de mot de passe
	tmpl := template.Must(template.ParseFiles("templates/reset-password.html"))
	tmpl.Execute(w, struct{ Token string }{Token: token})
}
resetToken, err := models.GetValidPasswordResetToken(token)
if err != nil {
	http.Error(w, "Jeton de réinitialisation de mot de passe invalide ou expiré", http.StatusBadRequest)
	return
}