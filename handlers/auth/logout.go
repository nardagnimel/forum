package handlers

import (
	"net/http"

	"forum/sessions"
)

// LogoutHandler gère la déconnexion des utilisateurs
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	// Supprimer la session de l'utilisateur
	sessionManager := sessions.NewManager()
	sessionID, err := sessionManager.GetSessionID(r)
	if err != nil {
		http.Error(w, "Erreur lors de la suppression de la session", http.StatusInternalServerError)
		return
	}
	sessionManager.DeleteSession(sessionID)

	// Supprimer le cookie de session
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	// Rediriger l'utilisateur vers la page d'accueil
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}
