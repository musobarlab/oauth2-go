package repository

import (
	"github.com/wuriyanto48/oauth2-go/core/application/model"
)

// Output struct
type Output struct {
	Result interface{}
	Error  error
}

// Repository interface
type Repository interface {
	Save(*model.Application) Output
	FindByID(string) Output
	FindAll() Output
}
