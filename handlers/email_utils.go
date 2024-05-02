package handlers

import (
	"database/sql"
	"fmt"
	"forum/database"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// isValidPassword vérifie si un mot de passe est fort ou faible en utilisant des règles prédéfinies
func isValidPassword(password string) bool {
	// Vérifier que le mot de passe contient au moins 8 caractères
	if len(password) < 8 {
		return false
	}

	// Vérifier que le mot de passe contient au moins une lettre majuscule
	if !strings.ContainsAny(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		return false
	}

	// Vérifier que le mot de passe contient au moins une lettre minuscule
	if !strings.ContainsAny(password, "abcdefghijklmnopqrstuvwxyz") {
		return false
	}

	// Vérifier que le mot de passe contient au moins un chiffre
	if !strings.ContainsAny(password, "0123456789") {
		return false
	}

	// Vérifier que le mot de passe contient au moins un caractère spécial
	if !strings.ContainsAny(password, "!@#$%^&*()-_=+{}[]|;:,.<>?/") {
		return false
	}

	// Le mot de passe est fort
	return true
}
func isValidEmail(email string) bool {
	regex := `^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`
	return regexp.MustCompile(regex).MatchString(email)
}

// sendUnlockAccountEmail envoie un e-mail de confirmation de déverrouillage de compte à l'utilisateur
func SendUnlockAccountEmail(email, unlockURL string) error {
	// Créer le message d'e-mail
	subject := "Confirmation de déverrouillage de compte"
	body := fmt.Sprintf("Votre compte a été déverrouillé. Cliquez sur le lien suivant pour confirmer le déverrouillage : %s", unlockURL)

	// Envoyer l'e-mail en utilisant le service de messagerie
	msg := mail.NewMessage()
	msg.SetHeader("From", "noreply@example.com")
	msg.SetHeader("To", email)
	msg.SetHeader("Subject", subject)
	msg.SetBody("text/plain", body)
	return mail.Send(msg)
}
//deverouillage de compte
func UnlockUserAccount(userID int, db *sql.DB) error {
	_, err := db.Exec("UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?", userID)
	return err
}


// sendResetPasswordEmail envoie un e-mail de réinitialisation de mot de passe à l'utilisateur
func SendResetPasswordEmail(email, resetURL string) error {
	// Créer le message d'e-mail
	subject := "Réinitialisation de mot de passe"
	body := fmt.Sprintf("Cliquez sur le lien suivant pour réinitialiser votre mot de passe : %s", resetURL)

	// Envoyer l'e-mail en utilisant le service de messagerie
	msg := mail.NewMessage()
	msg.SetHeader("From", "noreply@example.com")
	msg.SetHeader("To", email)
	msg.SetHeader("Subject", subject)
	msg.SetBody("text/plain", body)
	return mail.Send(msg)
}

// sendVerifyEmailEmail envoie un e-mail de vérification de compte à l'utilisateur
func SendVerifyEmail(email, verifyURL string) error {
	// Créer le message d'e-mail
	subject := "Vérification de compte"
	body := fmt.Sprintf("Cliquez sur le lien suivant pour vérifier votre compte : %s", verifyURL)

	// Envoyer l'e-mail en utilisant le service de messagerie
	var mail string
	msg := mail.NewMessage()
	msg.SetHeader("From", "noreply@example.com")
	msg.SetHeader("To", email)
	msg.SetHeader("Subject", subject)
	msg.SetBody("text/plain", body)
	return mail.Send(msg)
}
func sendVerifyEmail(email string, userID int, db *sql.DB) error {
	token := uuid.New().String()
	_, err := db.Exec("INSERT INTO email_verification_tokens (user_id, token) VALUES (?, ?)", userID, token)
	if err != nil {
		return err
	}
	verifyURL := fmt.Sprintf("http://%s/verify-email?token=%s", r.Host, url.QueryEscape(token))
	err = email_utils.SendVerifyEmail(email, verifyURL)
	return err
}


func GetUserID(r *http.Request) int {
	// Vérifier si un cookie de session est présent dans la requête
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return 0
	}

	// Vérifier le cookie de session dans la base de données pour obtenir l'ID utilisateur
	db := database.InitDB()
	var userID int
	err = db.QueryRow("SELECT user_id FROM sessions WHERE session_id = ?", cookie.Value).Scan(&userID)
	if err != nil {
		return 0
	}

	return userID
}

func isValidNewEmail(email string) (bool, error) {
	// Vérifier que l'adresse e-mail est valide
	if !isValidEmail(email) {
		return false, nil
	}

	// Vérifier que l'adresse e-mail n'est pas déjà utilisée
	var existingUser models.User
	err := database.InitDB().QueryRow("SELECT * FROM users WHERE email = ?", email).Scan(&existingUser.ID, &existingUser.Username, &existingUser.Email, &existingUser.Password, &existingUser.Activated, &existingUser.FailedLoginAttempts, &existingUser.LockedUntil)
	if err == nil {
		return false, nil
	}

	return true, nil
}

func GenerateEmailVerificationToken() string {
	return uuid.New().String()
}

// getUserByEmail récupère l'utilisateur à partir de la base de données en utilisant l'adresse e-mail
func GetUserByEmail(db *sql.DB, email string) (*models.User, error) {
	var user models.User
	err := db.QueryRow("SELECT id, username, email, password, activated, failed_login_attempts, locked_until FROM users WHERE email = ?", email).Scan(&user.ID, &user.Username, &user.Email, &user.Password, &user.Activated, &user.FailedLoginAttempts, &user.LockedUntil)
	if err == sql.ErrNoRows {
		ErrInvalidCredentials := 
		return nil, ErrInvalidCredentials
	} else if err != nil {
		return nil, err
	}
	return &user, nil
}

// checkPassword vérifie que le mot de passe correspond au hash stocké
func CheckPassword(hashedPassword string, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

// isAccountLocked vérifie si le compte de l'utilisateur est verrouillé
func isAccountLocked(user models.User) bool {
	return user.FailedLoginAttempts >= 5 && !user.LockedUntil.IsZero() && time.Now().Before(user.LockedUntil)
}

// recordFailedLoginAttempt enregistre une tentative de connexion infructueuse pour l'utilisateur
func RecordFailedLoginAttempt(db *sql.DB, user models.User) {
	user.FailedLoginAttempts++
	if user.FailedLoginAttempts >= 5 {
		user.LockedUntil = time.Now().Add(time.Hour * 1)
	}
	db.Exec("UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?", user.FailedLoginAttempts, user.LockedUntil, user.ID)
}

// resetFailedLoginAttempts réinitialise les tentatives de connexion infructueuses pour l'utilisateur et déverrouille le compte si nécessaire
func ResetFailedLoginAttempts(db *sql.DB, user models.User) {
	user.FailedLoginAttempts = 0
	user.LockedUntil = time.Time{}
	db.Exec("UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?", user.FailedLoginAttempts, user.LockedUntil, user.ID)
}

// createSession crée une nouvelle session pour l'utilisateur dans la base de données
func CreateSession(db *sql.DB, userID int) string {
	sessionID := uuid.New().String()
	db.Exec("INSERT INTO sessions (session_id, user_id) VALUES (?, ?)", sessionID, userID)
	return sessionID
}

// createSessionCookie crée un cookie de session pour l'utilisateur
func CreateSessionCookie(w http.ResponseWriter, sessionID string) {
	cookie := http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   3600, // Durée de vie du cookie de 1 heure
	}
	http.SetCookie(w, &cookie)
}
func GetValidPasswordResetToken(token string) (*models.PasswordResetToken, error) {
	db := database.InitDB()
	var passwordResetToken models.PasswordResetToken
	err := db.QueryRow("SELECT * FROM password_reset_tokens WHERE token = ?", token).Scan(&passwordResetToken.ID, &passwordResetToken.UserID, &passwordResetToken.Token, &passwordResetToken.CreatedAt)
	if err != nil {
		return nil, err
	}
	if time.Since(passwordResetToken.CreatedAt) > time.Hour*24 {
		return nil, fmt.Errorf("jeton de réinitialisation de mot de passe expiré")
	}
	return &passwordResetToken, nil
}

func CreatePasswordResetToken(userID int, db *sql.DB) (string, error) {
	token := uuid.New().String()
	expiration := time.Now().Add(time.Hour)
	_, err := db.Exec("INSERT INTO password_reset_tokens (user_id, token, expiration) VALUES (?, ?, ?)", userID, token, expiration)
	if err != nil {
		return "", err
	}
	return token, nil
}

func ActivateUserAccount(token string, db *sql.DB) error {
	var emailVerificationToken models.EmailVerificationToken
	err := db.QueryRow("SELECT * FROM email_verification_tokens WHERE token = ?", token).Scan(&emailVerificationToken.ID, &emailVerificationToken.UserID, &emailVerificationToken.Token, &emailVerificationToken.CreatedAt)
	if err != nil {
		return fmt.Errorf("jeton de vérification de compte invalide ou expiré")
	}
	if time.Since(emailVerificationToken.CreatedAt) > time.Hour*24 {
		return fmt.Errorf("jeton de vérification de compte expiré")
	}
	_, err = db.Exec("UPDATE users SET activated = true WHERE id = ?", emailVerificationToken.UserID)
	if err != nil {
		return err
	}
	_, err = db.Exec("DELETE FROM email_verification_tokens WHERE id = ?", emailVerificationToken.ID)
	return err
}
