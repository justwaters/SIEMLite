package storage

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Friendly lists hold addresses and ranges an admin trusts (an office, a
// scanner they run, a partner): the threat intel check never flags them.

// ErrFriendlyListNotFound is returned for an unknown list id.
var ErrFriendlyListNotFound = errors.New("there is no such list")

// ErrFriendlyNameTaken is returned when a list name is already used.
var ErrFriendlyNameTaken = errors.New("a list with that name already exists")

// FriendlyEntry is one address (1.2.3.4) or range (1.2.3.0/24) in a list.
type FriendlyEntry struct {
	Value     string `json:"value"`
	Note      string `json:"note,omitempty"`
	CreatedAt int64  `json:"created_at"`
}

// FriendlyList is a named list and its entries.
type FriendlyList struct {
	ID          int64           `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	CreatedAt   int64           `json:"created_at"`
	Entries     []FriendlyEntry `json:"entries"`
}

func isUnique(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// CreateFriendlyList makes an empty list.
func (r *Repository) CreateFriendlyList(ctx context.Context, name, description string, nowMs int64) (int64, error) {
	res, err := r.db.Write.ExecContext(ctx, `INSERT INTO friendly_lists (name, description, created_at) VALUES (?, ?, ?)`, name, description, nowMs)
	if isUnique(err) {
		return 0, ErrFriendlyNameTaken
	}
	if err != nil {
		return 0, fmt.Errorf("create friendly list: %w", err)
	}
	return res.LastInsertId()
}

// UpdateFriendlyList renames a list or changes its description.
func (r *Repository) UpdateFriendlyList(ctx context.Context, id int64, name, description string) error {
	res, err := r.db.Write.ExecContext(ctx, `UPDATE friendly_lists SET name = ?, description = ? WHERE id = ?`, name, description, id)
	if isUnique(err) {
		return ErrFriendlyNameTaken
	}
	if err != nil {
		return fmt.Errorf("update friendly list: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrFriendlyListNotFound
	}
	return r.bumpIntel(ctx)
}

// DeleteFriendlyList removes a list and its entries.
func (r *Repository) DeleteFriendlyList(ctx context.Context, id int64) (string, error) {
	tx, err := r.db.Write.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var name string
	if err := tx.QueryRowContext(ctx, `SELECT name FROM friendly_lists WHERE id = ?`, id).Scan(&name); err != nil {
		return "", ErrFriendlyListNotFound
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM friendly_entries WHERE list_id = ?`, id); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM friendly_lists WHERE id = ?`, id); err != nil {
		return "", err
	}
	if err := bumpIntelVersion(ctx, tx); err != nil {
		return "", err
	}
	return name, tx.Commit()
}

// AddFriendlyEntries adds entries (already normalized) to a list, keeping the ones it has.
// It returns how many were new.
func (r *Repository) AddFriendlyEntries(ctx context.Context, id int64, values []string, note string, nowMs int64) (int, error) {
	tx, err := r.db.Write.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var one int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM friendly_lists WHERE id = ?`, id).Scan(&one); err != nil {
		return 0, ErrFriendlyListNotFound
	}
	added := 0
	for _, v := range values {
		res, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO friendly_entries (list_id, value, note, created_at) VALUES (?, ?, ?, ?)`, id, v, note, nowMs)
		if err != nil {
			return 0, fmt.Errorf("add friendly entry: %w", err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			added++
		}
	}
	if err := bumpIntelVersion(ctx, tx); err != nil {
		return 0, err
	}
	return added, tx.Commit()
}

// DeleteFriendlyEntry removes one entry; it reports whether there was one.
func (r *Repository) DeleteFriendlyEntry(ctx context.Context, id int64, value string) (bool, error) {
	res, err := r.db.Write.ExecContext(ctx, `DELETE FROM friendly_entries WHERE list_id = ? AND value = ?`, id, value)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		return true, r.bumpIntel(ctx)
	}
	return false, nil
}

func (r *Repository) bumpIntel(ctx context.Context) error {
	_, err := r.db.Write.ExecContext(ctx, `UPDATE intel_state SET version = version + 1 WHERE id = 1`)
	return err
}

// FriendlyLists returns every list with its entries, by name.
func (r *Repository) FriendlyLists(ctx context.Context) ([]FriendlyList, error) {
	rows, err := r.db.Read.QueryContext(ctx, `SELECT id, name, description, created_at FROM friendly_lists ORDER BY name COLLATE NOCASE`)
	if err != nil {
		return nil, fmt.Errorf("list friendly lists: %w", err)
	}
	var out []FriendlyList
	idx := map[int64]int{}
	for rows.Next() {
		var l FriendlyList
		if err := rows.Scan(&l.ID, &l.Name, &l.Description, &l.CreatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		l.Entries = []FriendlyEntry{}
		idx[l.ID] = len(out)
		out = append(out, l)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	er, err := r.db.Read.QueryContext(ctx, `SELECT list_id, value, note, created_at FROM friendly_entries ORDER BY created_at DESC, value`)
	if err != nil {
		return nil, fmt.Errorf("list friendly entries: %w", err)
	}
	defer er.Close()
	for er.Next() {
		var id int64
		var e FriendlyEntry
		if err := er.Scan(&id, &e.Value, &e.Note, &e.CreatedAt); err != nil {
			return nil, err
		}
		if i, ok := idx[id]; ok {
			out[i].Entries = append(out[i].Entries, e)
		}
	}
	return out, er.Err()
}

// FriendlyValues returns every entry of every list (addresses and ranges), for matching.
func (r *Repository) FriendlyValues(ctx context.Context) ([]string, error) {
	rows, err := r.db.Read.QueryContext(ctx, `SELECT DISTINCT value FROM friendly_entries`)
	if err != nil {
		return nil, fmt.Errorf("read friendly entries: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
