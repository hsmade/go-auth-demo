package model

type ModelInterface interface {
	GetUser(username string) (UserInterface, error)
}

// Model holds connection to the DB and exposes an abstract API
type Model struct {
}

type UserInterface interface {
	ValidateLogin(password string) bool
}

// User models a user object with the information that the methods need
type User struct {
	password string
}

// GetUser retrieves a user from the DB, or returns an error
func (m *Model) GetUser(username string) (UserInterface, error) {
	if username == "user1" {
		return &User{
			password: "password1",
		}, nil
	}
	return nil, nil // todo: implement
}

// ValidateLogin will check if the password is correct for this user
func (u *User) ValidateLogin(password string) bool {
	return u.password == password
}
