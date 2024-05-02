package middleware

import (
	"context"
	"forum/sessions"
	"net/http"
)

// RequireAuth est un middleware qui vérifie que l'utilisateur est authentifié avant d'accorder l'accès à la route
func RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Récupérer l'ID utilisateur à partir du cookie de session
		userID, err := sessions.GetUserIDFromCookie(r)
		if err != nil {
			// Si le cookie de session est invalide, rediriger l'utilisateur vers la page de connexion
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Ajouter l'ID utilisateur à la requête pour qu'il soit disponible dans le gestionnaire de route
		type userIDKey string
		const userIDContextKey userIDKey = "user_id"
		ctx := context.WithValue(r.Context(), userIDContextKey, userID)

		r = r.WithContext(context.WithValue(r.Context(), userIDKey("user_id"), userID))
		r = r.WithContext(ctx)

		// Appeler le gestionnaire de route suivant
		next.ServeHTTP(w, r)
	}
}
