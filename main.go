package main

import (
	"fmt"
	"github.com/hsmade/authTest/pkg/web"
	"github.com/sirupsen/logrus"
	"log"
	"net/http"
)


func main() {
	w := web.New()
	logrus.SetLevel(logrus.DebugLevel)

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var claims *web.JwtClaims
		claims = r.Context().Value("claims").(*web.JwtClaims)
		w.Write([]byte(fmt.Sprintf("Welcome %s!\n", claims.Username)))
	})

	http.HandleFunc("/token/create", w.CreateToken)
	http.Handle("/test", w.ValidateToken(testHandler))
	http.HandleFunc("/token/refresh", w.RefreshToken)

	log.Fatal(http.ListenAndServe(":8000", nil))
}
