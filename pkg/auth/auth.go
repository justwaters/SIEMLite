// Package auth implements API-key authentication with read/write/admin roles.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"siemlite/pkg/storage"
)

// Role is a key's permission level.
type Role string

const (
	// RoleWrite may ingest events and logs only. Give this to applications.
	RoleWrite Role = "write"
	// RoleRead may search and see detailed health. Give this to analysts/UI.
	RoleRead Role = "read"
	// RoleAdmin may do everything.
	RoleAdmin Role = "admin"
)

// KeyPrefix makes keys recognizable to secret scanners.
const KeyPrefix = "slk_"

var (
	ErrMissing = errors.New("missing API key")
	ErrInvalid = errors.New("invalid or revoked API key")
)

// ParseRole validates a role name.
func ParseRole(s string) (Role, error) {
	switch r := Role(s); r {
	case RoleRead, RoleWrite, RoleAdmin:
		return r, nil
	}
	return "", fmt.Errorf("role must be one of read, write, admin (got %q)", s)
}

// Allows reports whether a holder of r may perform an action needing need.
func (r Role) Allows(need Role) bool { return r == RoleAdmin || r == need }

// GenerateKey returns a new random key and its storage hash.
func GenerateKey() (plaintext, hash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("generate key: %w", err)
	}
	plaintext = KeyPrefix + base64.RawURLEncoding.EncodeToString(b)
	return plaintext, HashKey(plaintext), nil
}

// HashKey returns the hex SHA-256 of a key. Keys carry 256 bits of entropy,
// so a fast unsalted hash is sufficient (there is nothing to brute-force).
func HashKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// CreateKey generates, stores and returns a new key. The plaintext is only
// available from this call.
func CreateKey(ctx context.Context, repo *storage.Repository, name string, role Role) (id int64, plaintext string, err error) {
	if strings.TrimSpace(name) == "" {
		return 0, "", errors.New("key name is required")
	}
	plaintext, hash, err := GenerateKey()
	if err != nil {
		return 0, "", err
	}
	id, err = repo.CreateKey(ctx, name, string(role), hash, time.Now().UnixMilli())
	return id, plaintext, err
}

// Authenticator validates bearer keys against the database.
type Authenticator struct {
	repo *storage.Repository
	log  *slog.Logger
}

// New returns an Authenticator.
func New(repo *storage.Repository, log *slog.Logger) *Authenticator {
	if log == nil {
		log = slog.Default()
	}
	return &Authenticator{repo: repo, log: log}
}

// Authenticate resolves the request's bearer key. It returns ErrMissing or
// ErrInvalid for client errors; any other error is an internal failure.
func (a *Authenticator) Authenticate(r *http.Request) (*storage.APIKey, error) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" {
		return nil, ErrMissing
	}
	key, err := a.repo.FindActiveKey(r.Context(), HashKey(strings.TrimSpace(token)))
	if errors.Is(err, storage.ErrKeyNotFound) {
		return nil, ErrInvalid
	}
	return key, err
}

// Require wraps next so only keys allowed to act as need get through.
func (a *Authenticator) Require(need Role, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key, err := a.Authenticate(r)
		switch {
		case errors.Is(err, ErrMissing), errors.Is(err, ErrInvalid):
			a.log.Warn("auth rejected", "path", r.URL.Path, "remote", r.RemoteAddr, "reason", err.Error())
			w.Header().Set("WWW-Authenticate", `Bearer realm="siemlite"`)
			deny(w, http.StatusUnauthorized, err.Error())
			return
		case err != nil:
			a.log.Error("auth lookup failed", "err", err)
			deny(w, http.StatusInternalServerError, "authentication unavailable")
			return
		}
		if !Role(key.Role).Allows(need) {
			a.log.Warn("auth forbidden", "path", r.URL.Path, "key", key.Name, "role", key.Role, "need", string(need))
			deny(w, http.StatusForbidden, fmt.Sprintf("key %q (role %s) cannot perform this action", key.Name, key.Role))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func deny(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
