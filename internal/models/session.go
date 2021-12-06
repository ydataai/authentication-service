package models

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/ydataai/go-core/pkg/common/logging"
)

// SessionStorage is a struct to temporarily saving the session.
type SessionStorage struct {
	configuration SessionStorageConfiguration
	sessions      map[string]*Session
	mtx           sync.RWMutex
	logger        logging.Logger
}

// NewSessionStorage creates a new temporary session and saves for validation.
func NewSessionStorage(logger logging.Logger, config SessionStorageConfiguration) *SessionStorage {
	ss := &SessionStorage{
		configuration: config,
		logger:        logger,
		sessions:      make(map[string]*Session),
	}

	// session is deleted at MaxTTL (configurable).
	go func() {
		for now := range time.Tick(time.Second * 5) {
			ss.mtx.Lock()
			for key, value := range ss.sessions {
				if now.Unix()-value.lastAccess > int64(config.MaxTTL) {
					delete(ss.sessions, key)
				}
			}
			ss.mtx.Unlock()
		}
	}()

	return ss
}

// CreateSession creates a new session and saves it to memory.
func (ss *SessionStorage) CreateSession() *Session {
	session := NewSession(ss.logger)
	ss.mtx.Lock()
	ss.sessions[session.State] = session
	ss.mtx.Unlock()

	return session
}

// GetSession gets the session that have been saved in memory.
func (ss *SessionStorage) GetSession(r *http.Request) *Session {
	state := r.URL.Query().Get("state")
	if state == "" {
		ss.logger.Error("the state returned from the OIDC Provider is null")
		return nil
	}

	ss.mtx.RLock()
	defer ss.mtx.RUnlock()

	if session, ok := ss.sessions[state]; ok {
		return session
	}
	ss.logger.Error("state did not match")
	return nil
}

// Session is a struct to temporarily saving state and nonce.
type Session struct {
	// State is there to protect the end user from cross site request forgery(CSRF) attacks.
	// It is introduced from OAuth 2.0 protocol RFC6749 (https://www.rfc-editor.org/rfc/rfc6749#section-10.12).
	// Protocol states that:
	// Once authorization has been obtained from the end-user, the authorization server redirects
	// the end-user's user-agent back to the client with the required binding value contained in
	// the "state" parameter. The binding value enables the client to verify the validity of the
	// request by matching the binding value to the user-agent's authenticated state.
	State string

	// Nonce serves as a token validation parameter and is introduced from OIDC specification.
	// https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowSteps
	// According to Google, you should enforce protection against replay attacks by ensuring
	// it is presented only once.
	Nonce string

	lastAccess int64
	logger     logging.Logger
}

// NewSession creates a new session.
func NewSession(logger logging.Logger) *Session {
	state, err := randomString(16)
	if err != nil {
		logger.Error("An error occurred while creating a temporary state.")
		state = ""
	}
	nonce, err := randomString(16)
	if err != nil {
		logger.Error("An error occurred while creating a temporary nonce.")
		nonce = ""
	}

	return &Session{
		State:      state,
		Nonce:      nonce,
		lastAccess: time.Now().Unix(),
		logger:     logger,
	}
}

// MatchNonce matches the nonce saved earlier with the nonce claim of the ID Token.
func (s *Session) MatchNonce(nonce string, r *http.Request) bool {
	if nonce != s.Nonce {
		s.logger.Error("nonce did not match")
		return false
	}

	return true
}

// randomString creates a random string and does a base64 encoding.
func randomString(nByte int) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
