package controlplane

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

const (
	defaultSessionTTL  = 24 * time.Hour
	defaultSessionIdle = 4 * time.Hour
	sessionCookieName  = "firefik_session"
)

var (
	ErrSessionUnknown = errors.New("session unknown")
	ErrSessionExpired = errors.New("session expired")
)

type Session struct {
	ID        string
	Username  string
	IssuedAt  time.Time
	ExpiresAt time.Time
	LastSeen  time.Time
}

type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]Session
	ttl      time.Duration
	idle     time.Duration
}

func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions: map[string]Session{},
		ttl:      defaultSessionTTL,
		idle:     defaultSessionIdle,
	}
}

func (s *SessionStore) WithTTL(ttl, idle time.Duration) *SessionStore {
	if ttl > 0 {
		s.ttl = ttl
	}
	if idle > 0 {
		s.idle = idle
	}
	return s
}

func (s *SessionStore) Create(username string) (Session, error) {
	id, err := newSessionID()
	if err != nil {
		return Session{}, err
	}
	now := time.Now().UTC()
	sess := Session{
		ID:        id,
		Username:  username,
		IssuedAt:  now,
		ExpiresAt: now.Add(s.ttl),
		LastSeen:  now,
	}
	s.mu.Lock()
	s.sessions[id] = sess
	s.mu.Unlock()
	return sess, nil
}

func (s *SessionStore) Touch(id string) (Session, error) {
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return Session{}, ErrSessionUnknown
	}
	if now.After(sess.ExpiresAt) {
		delete(s.sessions, id)
		return Session{}, ErrSessionExpired
	}
	if s.idle > 0 && now.Sub(sess.LastSeen) > s.idle {
		delete(s.sessions, id)
		return Session{}, ErrSessionExpired
	}
	sess.LastSeen = now
	s.sessions[id] = sess
	return sess, nil
}

func (s *SessionStore) Revoke(id string) {
	s.mu.Lock()
	delete(s.sessions, id)
	s.mu.Unlock()
}

func (s *SessionStore) Sweep() int {
	now := time.Now().UTC()
	removed := 0
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.sessions {
		if now.After(sess.ExpiresAt) || (s.idle > 0 && now.Sub(sess.LastSeen) > s.idle) {
			delete(s.sessions, id)
			removed++
		}
	}
	return removed
}

func newSessionID() (string, error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf[:]), nil
}
