package models

import (
	"fmt"
	"forum/database"
	"time"
)

func GetValidAccountActivationToken(token string) (*models.AccountActivationToken, error) {
	db, err := database.OpenDB()
	var activationToken models.AccountActivationToken
	err = db.QueryRow("SELECT * FROM account_activation_tokens WHERE token = ?", token).Scan(&activationToken.ID, &activationToken.UserEmail, &activationToken.Token, &activationToken.CreatedAt)
	if err != nil {
		return nil, err
	}
	if time.Since(activationToken.CreatedAt) > time.Hour*24 {
		return nil, fmt.Errorf("jeton d'activation de compte expiré")
	}
	return &activationToken, nil
}
