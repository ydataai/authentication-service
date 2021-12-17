package storages

import (
	"errors"
	"sync"

	"github.com/ydataai/authentication-service/internal/models"
)

// SessionStorage is a struct to temporarily saving the session.
type SessionStorage struct {
	sessions map[string]models.Session
	mtx      sync.RWMutex
}

// NewSessionStorage creates a new temporary session and saves for validation.
func NewSessionStorage() *SessionStorage {
	return &SessionStorage{
		sessions: make(map[string]models.Session),
	}
}

// StoreSession stores a new session in memory.
func (ss *SessionStorage) StoreSession(session models.Session) {
	ss.mtx.Lock()
	ss.sessions[session.State] = session
	ss.mtx.Unlock()
}

// GetSession gets the session that have been saved in memory.
func (ss *SessionStorage) GetSession(state string) (models.Session, error) {
	ss.mtx.RLock()
	defer ss.mtx.RUnlock()

	if session, ok := ss.sessions[state]; ok {
		return session, nil
	}

	return models.Session{}, errors.New("state did not match")
}
