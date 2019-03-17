package repository

import (
	"github.com/wuriyanto48/oauth2-go/core/user/model"
)

// Output struct
type Output struct {
	Result interface{}
	Error  error
}

// Repository interface
type Repository interface {
	Save(*model.User) Output
	FindByID(string) Output
	FindByEmail(string) Output
	FindAll() Output
}
