package model

// User struct
type User struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// IsValidPassword function
func (u *User) IsValidPassword(password string) bool {
	return u.Password == password
}
