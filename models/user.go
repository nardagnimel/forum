package models

import (
	"errors"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID                  uint      `gorm:"primary_key" json:"id"`
	Username            string    `gorm:"unique;not null" json:"username"`
	Email               string    `gorm:"unique;not null" json:"email"`
	Password            string    `gorm:"not null" json:"-"`
	Activated           bool      `json:"activated"`
	FailedLoginAttempts int       `json:"failed_login_attempts"`
	LockedUntil         time.Time `json:"locked_until"`
}

type PasswordResetToken struct {
	ID        int64     `json:"id"`
	UserID    int64     `json:"user_id"`
	Token     string    `json:"token"`
	CreatedAt time.Time `json:"created_at"`
}

type AccountActivationToken struct {
	ID     int64     `json:"id"`
	UserID int64     `json:"user_id"`
	Token  string    `json:"token"`
	Expiry time.Time `json:"expiry"`
}

type EmailVerificationToken struct {
	ID        int
	UserID    int
	Token     string
	CreatedAt time.Time
}

var jwtKey = []byte("votre_clé_secrète_ici")

// Token représente un jeton JWT
type Token struct {
	UserID uint `json:"user_id"`
	jwt.StandardClaims
}

// ParseToken prend une chaîne de jeton et renvoie un objet Token et une erreur
func ParseToken(tokenString string) (*Token, error) {
	claims := &Token{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("jeton invalide")
	}
	return claims, nil
}
func (u *User) BeforeSave() error {
	if u.Password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		u.Password = string(hashedPassword)
	}
	return nil
}
