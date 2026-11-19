package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// Proposal states.
const (
	ProposalPending   = "pending"
	ProposalAccepted  = "accepted"
	ProposalDismissed = "dismissed"
)

// ErrProposalNotFound means there is no such proposal, or it was already decided.
var ErrProposalNotFound = errors.New("that proposal isn't waiting for a decision")

// Proposal is an alert rule the AI Alerts integration suggests, with why. It
// changes nothing until a person accepts it, which makes it a real rule.
type Proposal struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	Description   string `json:"description"`
	Severity      int    `json:"severity"`
	Query         string `json:"query"`
	MinSeverity   *int   `json:"min_severity,omitempty"`
	GroupBy       string `json:"group_by"`
	Threshold     int    `json:"threshold"`
	WindowMinutes int    `json:"window_minutes"`
	Reasoning     string `json:"reasoning"`
	// Matched is how many events the rule's search found when it was proposed (at most 1000).
	Matched   int    `json:"matched"`
	Model     string `json:"model,omitempty"`
	Status    string `json:"status"`
	CreatedAt int64  `json:"created_at"`
	DecidedAt *int64 `json:"decided_at,omitempty"`
	DecidedBy string `json:"decided_by,omitempty"`
}

// Rule is the proposal as a rule, switched on.
func (p Proposal) Rule() Rule {
	return Rule{Name: p.Name, Description: p.Description, Kind: RuleMatch, Enabled: true, Severity: p.Severity, Query: p.Query,
		MinSeverity: p.MinSeverity, GroupBy: p.GroupBy, Threshold: p.Threshold, WindowMinutes: p.WindowMinutes}
}

const proposalCols = `id, name, description, severity, query, min_severity, group_by, threshold, window_minutes, reasoning, matched, model,
	status, created_at, decided_at, decided_by`

func scanProposal(sc interface{ Scan(...any) error }) (Proposal, error) {
	var p Proposal
	var minSev, decidedAt sql.NullInt64
	err := sc.Scan(&p.ID, &p.Name, &p.Description, &p.Severity, &p.Query, &minSev, &p.GroupBy, &p.Threshold, &p.WindowMinutes,
		&p.Reasoning, &p.Matched, &p.Model, &p.Status, &p.CreatedAt, &decidedAt, &p.DecidedBy)
	if minSev.Valid {
		v := int(minSev.Int64)
		p.MinSeverity = &v
	}
	if decidedAt.Valid {
		p.DecidedAt = &decidedAt.Int64
	}
	return p, err
}

// AddProposal stores a pending proposal.
func (r *Repository) AddProposal(ctx context.Context, p Proposal, nowMs int64) (int64, error) {
	res, err := r.db.Write.ExecContext(ctx, `INSERT INTO rule_proposals (name, description, severity, query, min_severity, group_by,
		threshold, window_minutes, reasoning, matched, model, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)`,
		p.Name, p.Description, p.Severity, p.Query, p.MinSeverity, p.GroupBy, p.Threshold, p.WindowMinutes, p.Reasoning, p.Matched, p.Model, nowMs)
	if err != nil {
		return 0, fmt.Errorf("add proposal: %w", err)
	}
	return res.LastInsertId()
}

// ListProposals returns proposals in a state (any if empty), newest first.
func (r *Repository) ListProposals(ctx context.Context, status string, limit int) ([]Proposal, error) {
	q := `SELECT ` + proposalCols + ` FROM rule_proposals`
	var args []any
	if status != "" {
		q += ` WHERE status = ?`
		args = append(args, status)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	rows, err := r.db.Read.QueryContext(ctx, q, append(args, limit)...)
	if err != nil {
		return nil, fmt.Errorf("list proposals: %w", err)
	}
	defer rows.Close()
	out := []Proposal{}
	for rows.Next() {
		p, err := scanProposal(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetProposal returns one proposal.
func (r *Repository) GetProposal(ctx context.Context, id int64) (Proposal, error) {
	p, err := scanProposal(r.db.Read.QueryRowContext(ctx, `SELECT `+proposalCols+` FROM rule_proposals WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrProposalNotFound
	}
	return p, err
}

// DecideProposal accepts or dismisses a pending proposal. Dismissed
// proposals stay, so the same suggestion isn't made again.
func (r *Repository) DecideProposal(ctx context.Context, id int64, status, by string, nowMs int64) error {
	res, err := r.db.Write.ExecContext(ctx, `UPDATE rule_proposals SET status = ?, decided_by = ?, decided_at = ? WHERE id = ? AND status = 'pending'`,
		status, by, nowMs, id)
	if err != nil {
		return fmt.Errorf("decide proposal: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrProposalNotFound
	}
	return nil
}

// ProposalKnown reports whether a proposal with this name or this search was
// already made (in any state), so the model isn't asked the same thing twice.
func (r *Repository) ProposalKnown(ctx context.Context, name, query string) (bool, error) {
	var n int
	err := r.db.Read.QueryRowContext(ctx, `SELECT COUNT(*) FROM rule_proposals WHERE name = ? COLLATE NOCASE
		OR (query <> '' AND query = ? COLLATE NOCASE)`, strings.TrimSpace(name), strings.TrimSpace(query)).Scan(&n)
	return n > 0, err
}

// CountPendingProposals returns how many proposals are waiting.
func (r *Repository) CountPendingProposals(ctx context.Context) (int, error) {
	var n int
	err := r.db.Read.QueryRowContext(ctx, `SELECT COUNT(*) FROM rule_proposals WHERE status = 'pending'`).Scan(&n)
	return n, err
}
