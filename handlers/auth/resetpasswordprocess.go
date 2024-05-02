package handlers

import (
	"forum/database"
	"forum/models"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

// ResetPasswordProcessHandler traite la demande et met à  jour la base de données avec le nouveau mot de passe
func ResetPasswordProcessHandler(w http.ResponseWriter, r *http.Request) {
	// Récupérer le jeton de réinitialisation de mot de passe à partir de l'URL
	token := r.FormValue("token")

	// Récupérer le nouveau mot de passe à partir du formulaire
	newPassword := r.FormValue("new_password")
	if newPassword == "" {
		http.Error(w, "Le nouveau mot de passe est requis", http.StatusBadRequest)
		return
	}

	// Vérifier que le jeton de réinitialisation de mot de passe est valide
	resetToken, err := models.GetValidPasswordResetToken(token)
	if err != nil {
		http.Error(w, "Jeton de réinitialisation de mot de passe invalide ou expiré", http.StatusBadRequest)
		return
	}

	// Mettre à jour le mot de passe de l'utilisateur dans la base de données
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Erreur lors de la génération du nouveau mot de passe", http.StatusInternalServerError)
		return
	}
	db := database.InitDB()
	_, err = db.Exec("UPDATE users SET password = ? WHERE id = ?", hashedPassword, resetToken.UserID)
	if err != nil {
		http.Error(w, "Erreur lors de la mise à jour du mot de passe de l'utilisateur", http.StatusInternalServerError)
		return
	}

	// Supprimer le jeton de réinitialisation de mot de passe de la base de données
	_, err = db.Exec("DELETE FROM password_reset_tokens WHERE token = ?", token)
	if err != nil {
		http.Error(w, "Erreur lors de la suppression du jeton de réinitialisation de mot de passe", http.StatusInternalServerError)
		return
	}

	// Rediriger l'utilisateur vers la page de connexion avec un message de succès
	http.Redirect(w, r, "/login?password_reset_success=true", http.StatusSeeOther)
}
