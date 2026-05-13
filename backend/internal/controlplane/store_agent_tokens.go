package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

const agentTokenPrefix = "agt_"

var (
	ErrAgentTokenUnknown = errors.New("agent token unknown")
	ErrAgentTokenRevoked = errors.New("agent token revoked")
)

func generateAgentTokenPlaintext() (string, error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	return agentTokenPrefix + hex.EncodeToString(buf[:]), nil
}

func hashAgentToken(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

func looksLikeAgentToken(plaintext string) bool {
	return strings.HasPrefix(plaintext, agentTokenPrefix)
}

func (s *sqliteStore) CreateAgentToken(ctx context.Context, name, description, issuedBy string) (AgentTokenIssued, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return AgentTokenIssued{}, errors.New("name required")
	}
	plaintext, err := generateAgentTokenPlaintext()
	if err != nil {
		return AgentTokenIssued{}, err
	}
	hash := hashAgentToken(plaintext)
	id := uuid.NewString()
	now := time.Now().UTC()
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO agent_tokens (id, token_hash, name, description, issued_by, issued_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, id, hash, name, strings.TrimSpace(description), strings.TrimSpace(issuedBy), now); err != nil {
		return AgentTokenIssued{}, err
	}
	return AgentTokenIssued{
		AgentToken: AgentToken{
			ID:          id,
			Name:        name,
			Description: strings.TrimSpace(description),
			IssuedBy:    strings.TrimSpace(issuedBy),
			IssuedAt:    now,
		},
		Token: plaintext,
	}, nil
}

func (s *sqliteStore) ListAgentTokens(ctx context.Context, includeRevoked bool) ([]AgentToken, error) {
	q := `SELECT id, name, description, issued_by, issued_at, last_used_at, last_used_ip, revoked_at FROM agent_tokens`
	if !includeRevoked {
		q += ` WHERE revoked_at IS NULL`
	}
	q += ` ORDER BY issued_at DESC`
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AgentToken
	for rows.Next() {
		t, err := scanAgentTokenRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *sqliteStore) GetAgentToken(ctx context.Context, id string) (AgentToken, bool, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, description, issued_by, issued_at, last_used_at, last_used_ip, revoked_at
		FROM agent_tokens WHERE id = ?
	`, id)
	t, err := scanAgentTokenRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return AgentToken{}, false, nil
	}
	if err != nil {
		return AgentToken{}, false, err
	}
	return t, true, nil
}

func (s *sqliteStore) RevokeAgentToken(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE agent_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
		time.Now().UTC(), id,
	)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrAgentTokenUnknown
	}
	return nil
}

func (s *sqliteStore) ValidateAgentToken(ctx context.Context, plaintext string) (AgentToken, error) {
	if plaintext == "" {
		return AgentToken{}, ErrAgentTokenUnknown
	}
	hash := hashAgentToken(plaintext)
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, description, issued_by, issued_at, last_used_at, last_used_ip, revoked_at
		FROM agent_tokens WHERE token_hash = ?
	`, hash)
	t, err := scanAgentTokenRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return AgentToken{}, ErrAgentTokenUnknown
	}
	if err != nil {
		return AgentToken{}, err
	}
	if t.RevokedAt != nil {
		return AgentToken{}, ErrAgentTokenRevoked
	}
	return t, nil
}

func (s *sqliteStore) TouchAgentToken(ctx context.Context, id, ip string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE agent_tokens SET last_used_at = ?, last_used_ip = ? WHERE id = ?`,
		time.Now().UTC(), nullIfEmpty(ip), id,
	)
	return err
}

func scanAgentTokenRow(r rowScanner) (AgentToken, error) {
	var t AgentToken
	var lastUsedAt sql.NullTime
	var lastUsedIP sql.NullString
	var revokedAt sql.NullTime
	if err := r.Scan(&t.ID, &t.Name, &t.Description, &t.IssuedBy, &t.IssuedAt, &lastUsedAt, &lastUsedIP, &revokedAt); err != nil {
		return AgentToken{}, err
	}
	if lastUsedAt.Valid {
		v := lastUsedAt.Time
		t.LastUsedAt = &v
	}
	if lastUsedIP.Valid {
		t.LastUsedIP = lastUsedIP.String
	}
	if revokedAt.Valid {
		v := revokedAt.Time
		t.RevokedAt = &v
	}
	return t, nil
}

type memAgentToken struct {
	rec  AgentToken
	hash string
}

func (m *memStore) CreateAgentToken(_ context.Context, name, description, issuedBy string) (AgentTokenIssued, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return AgentTokenIssued{}, errors.New("name required")
	}
	plaintext, err := generateAgentTokenPlaintext()
	if err != nil {
		return AgentTokenIssued{}, err
	}
	rec := AgentToken{
		ID:          uuid.NewString(),
		Name:        name,
		Description: strings.TrimSpace(description),
		IssuedBy:    strings.TrimSpace(issuedBy),
		IssuedAt:    time.Now().UTC(),
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.agentTokens == nil {
		m.agentTokens = map[string]memAgentToken{}
	}
	m.agentTokens[rec.ID] = memAgentToken{rec: rec, hash: hashAgentToken(plaintext)}
	return AgentTokenIssued{AgentToken: rec, Token: plaintext}, nil
}

func (m *memStore) ListAgentTokens(_ context.Context, includeRevoked bool) ([]AgentToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]AgentToken, 0, len(m.agentTokens))
	for _, v := range m.agentTokens {
		if !includeRevoked && v.rec.RevokedAt != nil {
			continue
		}
		out = append(out, v.rec)
	}
	sortAgentTokens(out)
	return out, nil
}

func (m *memStore) GetAgentToken(_ context.Context, id string) (AgentToken, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.agentTokens[id]
	if !ok {
		return AgentToken{}, false, nil
	}
	return v.rec, true, nil
}

func (m *memStore) RevokeAgentToken(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.agentTokens[id]
	if !ok || v.rec.RevokedAt != nil {
		return ErrAgentTokenUnknown
	}
	now := time.Now().UTC()
	v.rec.RevokedAt = &now
	m.agentTokens[id] = v
	return nil
}

func (m *memStore) ValidateAgentToken(_ context.Context, plaintext string) (AgentToken, error) {
	if plaintext == "" {
		return AgentToken{}, ErrAgentTokenUnknown
	}
	hash := hashAgentToken(plaintext)
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, v := range m.agentTokens {
		if v.hash == hash {
			if v.rec.RevokedAt != nil {
				return AgentToken{}, ErrAgentTokenRevoked
			}
			return v.rec, nil
		}
	}
	return AgentToken{}, ErrAgentTokenUnknown
}

func (m *memStore) TouchAgentToken(_ context.Context, id, ip string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.agentTokens[id]
	if !ok {
		return ErrAgentTokenUnknown
	}
	now := time.Now().UTC()
	v.rec.LastUsedAt = &now
	v.rec.LastUsedIP = strings.TrimSpace(ip)
	m.agentTokens[id] = v
	return nil
}

func sortAgentTokens(out []AgentToken) {
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].IssuedAt.After(out[i].IssuedAt) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
}
