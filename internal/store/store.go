package store

import "example.com/sandbox-demo/internal/model"

type Store interface {
	Save(*model.Sandbox) error
	Load(id string) (*model.Sandbox, error)
	Delete(id string) error
	List() ([]*model.Sandbox, error)
}
