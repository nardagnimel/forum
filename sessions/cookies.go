package sessions

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/gorilla/securecookie"
)

// CookieName est le nom du cookie utilisé pour stocker la session utilisateur
const CookieName = "session"

// MaxAge est la durée maximale de vie du cookie en secondes
const MaxAge = 86400 // 24 heures

// SecureCookie est une instance de gorilla/securecookie pour créer et vérifier les cookies
var SecureCookie = securecookie.New(
	securecookie.GenerateRandomKey(64),
	securecookie.GenerateRandomKey(32))

// CreateCookie crée un nouveau cookie sécurisé pour la session utilisateur
func CreateCookie(userID int, w http.ResponseWriter) error {
	// Créer une structure de données pour stocker les informations de session
	sessionData := map[string]int{
		"user_id": userID,
	}

	// Sérialiser les données de session en JSON
	sessionJSON, err := json.Marshal(sessionData)
	if err != nil {
		return err
	}

	// Encoder les données de session en base64
	encodedSession := base64.URLEncoding.EncodeToString(sessionJSON)

	// Créer un nouveau cookie avec les données de session encodées
	cookie := &http.Cookie{
		Name:     CookieName,
		Value:    encodedSession,
		Path:     "/",
		MaxAge:   MaxAge,
		Secure:   true,
		HttpOnly: true,
	}

	// Ajouter le cookie à la réponse HTTP
	http.SetCookie(w, cookie)

	return nil
}

// GetUserIDFromCookie récupère l'ID utilisateur à partir du cookie de session
func GetUserIDFromCookie(r *http.Request) (int, error) {
	// Récupérer le cookie de session à partir de la requête HTTP
	cookie, err := r.Cookie(CookieName)
	if err != nil {
		return 0, err
	}

	// Décoder les données de session à partir du cookie
	decodedSession, err := base64.URLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return 0, err
	}

	// Désérialiser les données de session en JSON
	var sessionData map[string]int
	err = json.Unmarshal(decodedSession, &sessionData)
	if err != nil {
		return 0, err
	}

	// Récupérer l'ID utilisateur à partir des données de session
	userID := sessionData["user_id"]

	return userID, nil
}

// ClearCookie supprime le cookie de session de la réponse HTTP
func ClearCookie(w http.ResponseWriter) {
	// Créer un nouveau cookie avec une durée de vie négative pour supprimer le cookie existant
	cookie := &http.Cookie{
		Name:     CookieName,
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
	}

	// Ajouter le cookie à la réponse HTTP pour supprimer le cookie existant
	http.SetCookie(w, cookie)
}
