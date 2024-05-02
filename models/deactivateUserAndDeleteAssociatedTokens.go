package models

import "database/sql"

func DesactivateUserAndDeleteAssociatedTokens(userID int, db *sql.DB) error {
	_, err := db.Exec("UPDATE users SET activated = false WHERE id = ?", userID)
	if err != nil {
		return err
	}
	_, err = db.Exec("DELETE FROM auth_tokens WHERE user_id = ?", userID)
	if err != nil {
		return err
	}
	_, err = db.Exec("DELETE FROM email_verification_tokens WHERE user_id = ?", userID)
	if err != nil {
		return err
	}
	_, err = db.Exec("DELETE FROM password_reset_tokens WHERE user_id = ?", userID)
	if err != nil {
		return err
	}
	return nil
}
