package repository

import (
	"fmt"

	"github.com/wuriyanto48/oauth2-go/core/user/model"
)

// InMemory struct
type InMemory struct {
	db map[string]*model.User
}

// NewInMemory function
func NewInMemory(db map[string]*model.User) *InMemory {
	return &InMemory{db}
}

// Save function
func (r *InMemory) Save(user *model.User) Output {
	r.db[user.ID] = user
	return Output{Result: user}
}

// FindByID function
func (r *InMemory) FindByID(id string) Output {
	user, ok := r.db[id]
	if !ok {
		return Output{Error: fmt.Errorf("user with id %s, not found", id)}
	}

	return Output{Result: user}
}

// FindByEmail function
func (r *InMemory) FindByEmail(email string) Output {
	var user *model.User
	if len(r.db) > 0 {
		for _, v := range r.db {
			if v.Email == email {
				user = v
				break
			} else {
				return Output{Error: fmt.Errorf("user with email %s, not found", email)}
			}
		}
	} else {
		return Output{Error: fmt.Errorf("user with email %s, not found", email)}
	}

	return Output{Result: user}
}

// FindAll function
func (r *InMemory) FindAll() Output {
	var list []*model.User

	for _, v := range r.db {
		list = append(list, v)
	}

	return Output{Result: list}
}
