package handlers

import (
	"net/http"

	"forum/database"

	"golang.org/x/crypto/bcrypt"
)

// ResetPasswordHandler traite la demande de réinitialisation de mot de passe
func ResetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	// Récupérer le jeton de réinitialisation de mot de passe à partir de l'URL
	token := r.URL.Query().Get("token")

	// Vérifier que le jeton de réinitialisation de mot de passe est valide
	passwordResetToken, err := email_utils.getValidPasswordResetToken(token)
	if err != nil {
		http.Error(w, "Jeton de réinitialisation de mot de passe invalide ou expiré", http.StatusBadRequest)
		return
	}

	// Récupérer le nouveau mot de passe à partir du formulaire
	newPassword := r.FormValue("new_password")

	// Mettre à jour le mot de passe de l'utilisateur dans la base de données
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Erreur lors de la génération du nouveau mot de passe", http.StatusInternalServerError)
		return
	}
	db := database.InitDB()
	_, err = db.Exec("UPDATE users SET password = ? WHERE id = ?", hashedPassword, passwordResetToken.UserID)
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
