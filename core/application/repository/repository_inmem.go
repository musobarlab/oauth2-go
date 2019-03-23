package repository

import (
	"fmt"

	"github.com/musobarlab/oauth2-go/core/application/model"
)

// InMemory struct
type InMemory struct {
	db map[string]*model.Application
}

// NewInMemory function
func NewInMemory(db map[string]*model.Application) *InMemory {
	return &InMemory{db}
}

// Save function
func (r *InMemory) Save(app *model.Application) Output {
	r.db[app.ClientID] = app
	return Output{Result: app}
}

// FindByID function
func (r *InMemory) FindByID(id string) Output {
	app, ok := r.db[id]
	if !ok {
		return Output{Error: fmt.Errorf("app with id %s, not found", id)}
	}

	return Output{Result: app}
}

// FindAll function
func (r *InMemory) FindAll() Output {
	var list []*model.Application

	for _, v := range r.db {
		list = append(list, v)
	}

	return Output{Result: list}
}
