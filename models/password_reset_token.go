package models

import (
	"fmt"
	"forum/database"
	"time"
)

// GetValidPasswordResetToken récupère un jeton de réinitialisation de mot de passe valide à partir de la base de données
func GetValidPasswordResetToken(token string) (*PasswordResetToken, error) {
	db, err := database.OpenDB()
	resetToken := user.models.PasswordResetToken{}

	err = db.QueryRow("SELECT * FROM password_reset_tokens WHERE token = ?", token).Scan(&resetToken.ID, &resetToken.UserID, &resetToken.Token, &resetToken.CreatedAt)
	if err != nil {
		return nil, err
	}
	if time.Since(resetToken.CreatedAt) > time.Hour*24 {
		return nil, fmt.Errorf("jeton de réinitialisation de mot de passe expiré")
	}
	return &resetToken, nil
}
