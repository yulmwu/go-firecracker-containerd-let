package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"example.com/sandbox-demo/internal/model"
)

type FileStore struct {
	baseDir string
}

func NewFileStore(baseDir string) (*FileStore, error) {
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return nil, err
	}

	return &FileStore{baseDir: baseDir}, nil
}

func (s *FileStore) Save(sb *model.Sandbox) error {
	b, err := json.MarshalIndent(sb, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(s.path(sb.ID), b, 0o644)
}

func (s *FileStore) Load(id string) (*model.Sandbox, error) {
	b, err := os.ReadFile(s.path(id))
	if err != nil {
		return nil, err
	}

	var sb model.Sandbox
	if err := json.Unmarshal(b, &sb); err != nil {
		return nil, err
	}

	return &sb, nil
}

func (s *FileStore) Delete(id string) error {
	err := os.Remove(s.path(id))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}

	return err
}

func (s *FileStore) List() ([]*model.Sandbox, error) {
	entries, err := os.ReadDir(s.baseDir)
	if err != nil {
		return nil, err
	}

	out := make([]*model.Sandbox, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}

		id := e.Name()[:len(e.Name())-5]
		sb, err := s.Load(id)
		if err == nil {
			out = append(out, sb)
		}
	}

	return out, nil
}

func (s *FileStore) path(id string) string {
	return filepath.Join(s.baseDir, id+".json")
}
