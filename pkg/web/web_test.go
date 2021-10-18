package web

import (
	"errors"
	"github.com/golang-jwt/jwt"
	"github.com/hsmade/authTest/pkg/model"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type ModelMock struct {
	Users map[string]*UserMock
}

func (m *ModelMock) GetUser(username string) (model.UserInterface, error) {
	user, ok := m.Users[username]
	if !ok {
		return user, errors.New("")
	}
	return user, nil
}

type UserMock struct {
	Valid bool
}

func (u *UserMock) ValidateLogin(password string) bool { return u.Valid }

func TestWeb_Signin(t *testing.T) {
	type fields struct {
		jwtKey []byte
	}
	tests := []struct {
		name   string
		fields fields
		wantCode int
		sendBody string
		wantCookie bool
		validLogin bool
	}{
		{
			name: "valid login",
			fields: fields{
				jwtKey: []byte("key"),
			},
			wantCode: 200,
			sendBody: `{"username":"user1","password":"password1"}`,
			wantCookie: true,
			validLogin: true,
		},
		{
			name: "invalid login",
			fields: fields{
				jwtKey: []byte("key"),
			},
			wantCode: 401,
			sendBody: `{"username":"user2","password":"password3"}`,
		},
		{
			name: "no login",
			fields: fields{
				jwtKey: []byte("key"),
			},
			wantCode: 400,
			sendBody: ``,
		},
	}
		for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			web := Web{
				jwtKey: tt.fields.jwtKey,
				expiry: time.Second,
				signingMethod: jwt.SigningMethodHS256,
				model: &ModelMock{
					Users: map[string]*UserMock{"user1": &UserMock{Valid: tt.validLogin}}},
			}

			req, err := http.NewRequest("GET", "/", strings.NewReader(tt.sendBody))
			if err != nil {
				t.Fatal(err)
			}

			rr := httptest.NewRecorder()

			web.CreateToken(rr, req)

			assert.Equal(t, tt.wantCode, rr.Code)

			if tt.wantCookie {
				if len(rr.Result().Cookies()) < 1 {
					t.Error("did not get any cookies")
				}
				t.Logf("cookies: %+v", rr.Result().Cookies())
			}
		})
	}
}
