package handlers

import (
	"net/http"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"forum/database"
	"forum/email_utils"
	"forum/models"
)

// LoginHandler gère la connexion des utilisateurs
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	// Récupérer les informations de connexion de l'utilisateur
	email := r.FormValue("email")
	password := r.FormValue("password")

	// Vérifier que toutes les informations ont été fournies
	if email == "" || password == "" {
		http.Error(w, "Toutes les informations doivent être fournies", http.StatusBadRequest)
		return
	}

	// Vérifier que les informations de connexion sont valides
	if !email_utils.IsValidEmail(email) {
		http.Error(w, "Adresse e-mail invalide", http.StatusUnauthorized)

	}
	if !email_utils.isValidPassword(password) {
		http.Error(w, "Mot de passe invalide", http.StatusBadRequest)
		return
	}

	// Vérifier les informations d'identification de l'utilisateur
	db := database.InitDB()/
	user, err := email_utils.getUserByEmail(db, email)
	if err != nil {
		http.Error(w, "Nom d'utilisateur ou mot de passe incorrect", http.StatusUnauthorized)
		return
	}

	// Vérifier que le compte de l'utilisateur est activé
	if !user.Activated {
		http.Error(w, "Compte non activé", http.StatusUnauthorized)
		return
	}

	// Vérifier que le compte de l'utilisateur n'est pas verrouillé
	if !user.LockedUntil.IsZero() && time.Now().Before(user.LockedUntil) {
		http.Error(w, "Compte verrouillé", http.StatusUnauthorized)
		return
	}

	// Vérifier que le mot de passe est correct
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		// Si le mot de passe est incorrect, nous augmentons le nombre de tentatives de connexion infructueuses de l'utilisateur
		user.FailedLoginAttempts++
		if user.FailedLoginAttempts >= 5 {
			// Si l'utilisateur a échoué à se connecter 5 fois de suite, nous verrouillons son compte pendant 1 heure
			user.LockedUntil = time.Now().Add(time.Hour * 1)
		}
		db.Exec("UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?", user.FailedLoginAttempts, user.LockedUntil, user.ID)

		http.Error(w, "Nom d'utilisateur ou mot de passe incorrect", http.StatusUnauthorized)
		return
	}

	// Si le mot de passe est correct, nous réinitialisons le nombre de tentatives de connexion infructueuses de l'utilisateur
	user.FailedLoginAttempts = 0
	user.LockedUntil = time.Time{}
	db.Exec("UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?", user.FailedLoginAttempts, user.LockedUntil, user.ID)

	// Créer un cookie de session pour l'utilisateur
	sessionID := uuid.New().String()
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

	// Enregistrer la session dans la base de données
	db.Exec("INSERT INTO sessions (session_id, user_id) VALUES (?, ?)", sessionID, user.ID)
}
