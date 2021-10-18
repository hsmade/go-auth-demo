// Package web implements JWT auth
package web

import (
	"context"
	"encoding/json"
	"github.com/golang-jwt/jwt"
	"github.com/hsmade/authTest/pkg/model"
	"github.com/sirupsen/logrus"
	"net/http"
	"time"
)

type Web struct {
	jwtKey []byte
	expiry time.Duration
	signingMethod jwt.SigningMethod
	model model.ModelInterface
}

func New() Web {
	// FIXME: implement
	return Web{
		jwtKey: []byte("my_secret_key"),
		expiry: time.Second * 5,
		signingMethod: jwt.SigningMethodHS256,
		model: &model.Model{},
	}
}

type CredentialsRequest struct {
	Password string `json:"password"`
	Username string `json:"username"`
}

type JwtClaims struct {
	Username string `json:"username"`
	IsAdmin bool `json:"is_admin"`
	jwt.StandardClaims
}

// CreateToken validates the credentials and creates a JWT
func (web Web) CreateToken(w http.ResponseWriter, r *http.Request) {
	logrus.WithFields(getLabels(r)).Debug("CreateToken(): called")
	var credentials CredentialsRequest
	// Get the JSON body and decode into credentials
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		logrus.WithFields(getLabels(r)).WithError(err).Warn("CreateToken(): failed to decode credentials")
		// If the structure of the body is wrong, return an HTTP error
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	user, err := web.model.GetUser(credentials.Username)
	if err != nil {
		logrus.WithFields(getLabels(r)).WithError(err).Warnf("CreateToken(): failed to get user '%s'", credentials.Username)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if !user.ValidateLogin(credentials.Password) {
		logrus.WithFields(getLabels(r)).Warnf("CreateToken(): failed to validate user '%s'", credentials.Username)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(web.expiry)
	// Create the JWT claims, which includes the username and expiry time
	claims := &JwtClaims{
		Username: credentials.Username,
		StandardClaims: jwt.StandardClaims{
			// In JWT, the expiry time is expressed as unix milliseconds
			ExpiresAt: expirationTime.Unix(),
		},
	}

	// Declare the token with the algorithm used for signing, and the claims
	token := jwt.NewWithClaims(web.signingMethod, claims)
	// Create the JWT string
	tokenString, err := token.SignedString(web.jwtKey)
	if err != nil {
		logrus.WithFields(getLabels(r)).WithError(err).Warnf("CreateToken(): failed to create token for user '%s'", credentials.Username)

		// If there is an error in creating the JWT return an internal server error
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Finally, we set the client cookie for "token" as the JWT we just generated
	// we also set an expiry time which is the same as the token itself
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
		Path: "/",
	})
	logrus.WithFields(getLabels(r)).Debugf("CreateToken(): succesfully created token for user '%s'", credentials.Username)

}

// GetLabels creates the labels for logging
func getLabels(r *http.Request) logrus.Fields {
	return logrus.Fields{
		"remote-addr": r.RemoteAddr,
		"url": r.RequestURI,
		"method": r.Method,
		"file": "pkg/web/web.go",
	}
}

// ValidateJWT validates the JWT
func (web Web) ValidateJWT(r *http.Request) *JwtClaims {
	logrus.WithFields(getLabels(r)).Debug("ValidateJWT(): called")
	tokenCookie, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			logrus.WithFields(getLabels(r)).Warn("ValidateJWT(): missing cookie 'token'")
			return nil
		}
		logrus.WithFields(getLabels(r)).WithError(err).Warn("ValidateJWT(): could not get cookie")
		return nil
	}

	jwtString := tokenCookie.Value
	claims := &JwtClaims{}

	token, err := jwt.ParseWithClaims(jwtString, claims, func(token *jwt.Token) (interface{}, error) {
		return web.jwtKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			logrus.WithFields(getLabels(r)).WithError(err).Warn("ValidateJWT(): invalid JWT")
			return nil
		}
		logrus.WithFields(getLabels(r)).WithError(err).Warn("ValidateJWT(): failed to parse JWT")
		return nil
	}

	// only accept the original signing method
	if token.Method != web.signingMethod {
		logrus.WithFields(getLabels(r)).Warn("ValidateJWT(): jwt has wrong signing method")
		return nil
	}

	if !token.Valid {
		logrus.WithFields(getLabels(r)).Warn("ValidateJWT(): jwt token invalid")
		return nil
	}

	logrus.WithFields(getLabels(r)).Debugf("ValidateJWT(): successfully validated token with claims: %+v", claims)
	return claims
}

// ValidateToken authenticates the token
func (web Web) ValidateToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logrus.WithFields(getLabels(r)).Debug("ValidateToken(): called")
		claims := web.ValidateJWT(r)
		if claims == nil{
			logrus.WithFields(getLabels(r)).Warn("ValidateToken(): token validation failed")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), "claims", claims)
		logrus.WithFields(getLabels(r)).Debug("ValidateToken(): token validation success")
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RefreshToken creates a new token, if the current one is valid
func (web Web) RefreshToken(w http.ResponseWriter, r *http.Request) {
	logrus.WithFields(getLabels(r)).Debug("RefreshToken(): called")
	claims := web.ValidateJWT(r)
	if claims == nil{
		logrus.WithFields(getLabels(r)).Warn("RefreshToken(): token validation failed")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// We ensure that a new token is not issued until enough time has elapsed
	// In this case, a new token will only be issued if the old token is within
	// 30 seconds of expiry. Otherwise, return a bad request status
	if time.Unix(claims.ExpiresAt, 0).Sub(time.Now()) > 30*time.Second {
		logrus.WithFields(getLabels(r)).Warn("RefreshToken(): token refresh not needed yet")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Now, create a new token for the current use, with a renewed expiration time
	expirationTime := time.Now().Add(web.expiry)
	claims.ExpiresAt = expirationTime.Unix()
	token := jwt.NewWithClaims(web.signingMethod, claims)
	tokenString, err := token.SignedString(web.jwtKey)
	if err != nil {
		logrus.WithFields(getLabels(r)).WithError(err).Warn("RefreshToken(): failed to refresh token")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Set the new token as the users `token` cookie
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
		Path: "/",
	})
	logrus.WithFields(getLabels(r)).Debug("RefreshToken(): token refresh done")
}
