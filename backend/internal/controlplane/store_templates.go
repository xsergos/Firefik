package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

var ErrTemplateNotFound = errors.New("template not found")

var ErrApprovalNotFound = errors.New("approval not found")

var ErrSelfApprove = errors.New("requester cannot approve their own request")

var ErrApprovalNotPending = errors.New("approval is not pending")

func (s *sqliteStore) PublishTemplate(ctx context.Context, t PolicyTemplate) (PolicyTemplate, error) {
	if t.Name == "" {
		return PolicyTemplate{}, errors.New("template name required")
	}
	now := time.Now().UTC()
	labelsJSON, _ := json.Marshal(t.Labels)
	res, err := s.db.ExecContext(ctx, `
        INSERT INTO policy_templates (name, version, body, labels_json, publisher, created_at, updated_at)
        VALUES (?, 1, ?, ?, ?, ?, ?)
        ON CONFLICT(name) DO UPDATE SET
            version=policy_templates.version + 1,
            body=excluded.body,
            labels_json=excluded.labels_json,
            publisher=excluded.publisher,
            updated_at=excluded.updated_at
    `, t.Name, t.Body, string(labelsJSON), nullIfEmpty(t.Publisher), now, now)
	if err != nil {
		return PolicyTemplate{}, err
	}
	_ = res
	return s.GetTemplate(ctx, t.Name)
}

func (s *sqliteStore) GetTemplate(ctx context.Context, name string) (PolicyTemplate, error) {
	row := s.db.QueryRowContext(ctx, `
        SELECT name, version, body, COALESCE(labels_json,''), COALESCE(publisher,''), created_at, updated_at
          FROM policy_templates
         WHERE name = ?
    `, name)
	var t PolicyTemplate
	var labelsJSON, publisher string
	if err := row.Scan(&t.Name, &t.Version, &t.Body, &labelsJSON, &publisher, &t.CreatedAt, &t.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return PolicyTemplate{}, ErrTemplateNotFound
		}
		return PolicyTemplate{}, err
	}
	t.Publisher = publisher
	if labelsJSON != "" && labelsJSON != "null" {
		var lbl map[string]string
		if err := json.Unmarshal([]byte(labelsJSON), &lbl); err == nil {
			t.Labels = lbl
		}
	}
	return t, nil
}

func (s *sqliteStore) ListTemplates(ctx context.Context) ([]PolicyTemplate, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT name, version, body, COALESCE(labels_json,''), COALESCE(publisher,''), created_at, updated_at
          FROM policy_templates
         ORDER BY name ASC
    `)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PolicyTemplate
	for rows.Next() {
		var t PolicyTemplate
		var labelsJSON, publisher string
		if err := rows.Scan(&t.Name, &t.Version, &t.Body, &labelsJSON, &publisher, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		t.Publisher = publisher
		if labelsJSON != "" && labelsJSON != "null" {
			var lbl map[string]string
			if err := json.Unmarshal([]byte(labelsJSON), &lbl); err == nil {
				t.Labels = lbl
			}
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *sqliteStore) CreateApproval(ctx context.Context, p PendingApproval) (PendingApproval, error) {
	if p.PolicyName == "" || p.ProposedBody == "" {
		return PendingApproval{}, errors.New("policy_name and proposed_body required")
	}
	if p.Requester == "" || p.RequesterFinger == "" {
		return PendingApproval{}, errors.New("requester and requester_fingerprint required")
	}
	if p.ID == "" {
		p.ID = newApprovalID(p.PolicyName, p.ProposedBody, p.RequesterFinger)
	}
	if p.RequestedAt.IsZero() {
		p.RequestedAt = time.Now().UTC()
	}
	if p.Status == "" {
		p.Status = ApprovalPending
	}
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO pending_approvals (id, policy_name, proposed_body, requester, requester_fingerprint, requested_at, status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    `, p.ID, p.PolicyName, p.ProposedBody, p.Requester, p.RequesterFinger, p.RequestedAt, string(p.Status))
	if err != nil {
		return PendingApproval{}, err
	}
	return p, nil
}

func (s *sqliteStore) GetApproval(ctx context.Context, id string) (PendingApproval, error) {
	row := s.db.QueryRowContext(ctx, `
        SELECT id, policy_name, proposed_body, requester, requester_fingerprint, requested_at,
               COALESCE(approver,''), COALESCE(approver_fingerprint,''), approved_at, status,
               COALESCE(rejection_comment,'')
          FROM pending_approvals
         WHERE id = ?
    `, id)
	return scanApproval(row)
}

func (s *sqliteStore) ListApprovals(ctx context.Context, status ApprovalStatus) ([]PendingApproval, error) {
	q := `SELECT id, policy_name, proposed_body, requester, requester_fingerprint, requested_at,
                 COALESCE(approver,''), COALESCE(approver_fingerprint,''), approved_at, status,
                 COALESCE(rejection_comment,'')
            FROM pending_approvals`
	args := []any{}
	if status != "" {
		q += ` WHERE status = ?`
		args = append(args, string(status))
	}
	q += ` ORDER BY requested_at DESC`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PendingApproval
	for rows.Next() {
		p, err := scanApproval(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *sqliteStore) ApproveApproval(ctx context.Context, id, approver, approverFinger string) (PendingApproval, error) {
	if approver == "" || approverFinger == "" {
		return PendingApproval{}, errors.New("approver and approver_fingerprint required")
	}
	current, err := s.GetApproval(ctx, id)
	if err != nil {
		return PendingApproval{}, err
	}
	if current.Status != ApprovalPending {
		return PendingApproval{}, ErrApprovalNotPending
	}
	if approverFinger == current.RequesterFinger {
		return PendingApproval{}, ErrSelfApprove
	}
	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx, `
        UPDATE pending_approvals
           SET approver = ?, approver_fingerprint = ?, approved_at = ?, status = 'approved'
         WHERE id = ? AND status = 'pending'
    `, approver, approverFinger, now, id)
	if err != nil {
		return PendingApproval{}, err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return PendingApproval{}, err
	}
	if affected == 0 {
		return PendingApproval{}, ErrApprovalNotPending
	}
	current.Approver = approver
	current.ApproverFinger = approverFinger
	current.ApprovedAt = &now
	current.Status = ApprovalApproved
	return current, nil
}

func (s *sqliteStore) RejectApproval(ctx context.Context, id, approver, approverFinger, comment string) (PendingApproval, error) {
	if approver == "" || approverFinger == "" {
		return PendingApproval{}, errors.New("approver and approver_fingerprint required")
	}
	current, err := s.GetApproval(ctx, id)
	if err != nil {
		return PendingApproval{}, err
	}
	if current.Status != ApprovalPending {
		return PendingApproval{}, ErrApprovalNotPending
	}
	if approverFinger == current.RequesterFinger {
		return PendingApproval{}, ErrSelfApprove
	}
	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx, `
        UPDATE pending_approvals
           SET approver = ?, approver_fingerprint = ?, approved_at = ?, status = 'rejected', rejection_comment = ?
         WHERE id = ? AND status = 'pending'
    `, approver, approverFinger, now, nullIfEmpty(comment), id)
	if err != nil {
		return PendingApproval{}, err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return PendingApproval{}, err
	}
	if affected == 0 {
		return PendingApproval{}, ErrApprovalNotPending
	}
	current.Approver = approver
	current.ApproverFinger = approverFinger
	current.ApprovedAt = &now
	current.Status = ApprovalRejected
	current.RejectionComment = comment
	return current, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanApproval(r rowScanner) (PendingApproval, error) {
	var p PendingApproval
	var approver, approverFinger, rejectionComment string
	var approvedAt sql.NullTime
	var status string
	if err := r.Scan(
		&p.ID, &p.PolicyName, &p.ProposedBody, &p.Requester, &p.RequesterFinger,
		&p.RequestedAt, &approver, &approverFinger, &approvedAt, &status, &rejectionComment,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return PendingApproval{}, ErrApprovalNotFound
		}
		return PendingApproval{}, err
	}
	p.Approver = approver
	p.ApproverFinger = approverFinger
	if approvedAt.Valid {
		t := approvedAt.Time
		p.ApprovedAt = &t
	}
	p.Status = ApprovalStatus(status)
	p.RejectionComment = rejectionComment
	return p, nil
}

func newApprovalID(policyName, body, finger string) string {
	h := sha256.New()
	h.Write([]byte(policyName))
	h.Write([]byte{0})
	h.Write([]byte(body))
	h.Write([]byte{0})
	h.Write([]byte(finger))
	h.Write([]byte{0})
	var nonce [8]byte
	_, _ = rand.Read(nonce[:])
	h.Write(nonce[:])
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:16])
}

var (
	_ = strings.TrimSpace
	_ = sort.Slice
	_ = fmt.Sprint
)
