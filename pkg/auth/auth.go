// Package auth authenticates callers. Two kinds exist and they are kept apart:
//
//   - API keys are for applications and can only send logs.
//   - Users sign in with a username and password (a browser session) and can
//     search; admins can also add logs from the UI.
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

// Permission is something a caller may do.
type Permission int

const (
	PermIngest Permission = iota + 1 // send events and logs
	PermSearch                       // search and read health details
)

// Kind says how a caller authenticated.
type Kind string

const (
	KindKey  Kind = "key"
	KindUser Kind = "user"
)

// User roles.
const (
	RoleAdmin   = "admin"   // search, add logs
	RoleAnalyst = "analyst" // search only
)

// KeyPrefix makes keys recognizable to secret scanners.
const KeyPrefix = "slk_"

var (
	ErrMissing = errors.New("authentication required")
	ErrInvalid = errors.New("invalid or revoked API key, or expired session")
)

// Principal is an authenticated caller.
type Principal struct {
	Kind Kind
	Name string
	Role string // users only
}

// Can reports whether the caller holds perm.
func (p *Principal) Can(perm Permission) bool {
	switch p.Kind {
	case KindKey:
		return perm == PermIngest
	case KindUser:
		switch p.Role {
		case RoleAdmin:
			return true
		case RoleAnalyst:
			return perm == PermSearch
		}
	}
	return false
}

type ctxKey struct{}

// FromContext returns the authenticated principal set by Require.
func FromContext(ctx context.Context) *Principal {
	p, _ := ctx.Value(ctxKey{}).(*Principal)
	return p
}

// GenerateKey returns a new random key and its storage hash.
func GenerateKey() (plaintext, hash string, err error) {
	plaintext, err = randomToken(KeyPrefix)
	if err != nil {
		return "", "", err
	}
	return plaintext, hashToken(plaintext), nil
}

// HashKey returns the hex SHA-256 of a key or session token. These carry 256
// bits of entropy, so a fast unsalted hash is sufficient.
func HashKey(key string) string { return hashToken(key) }

func hashToken(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

func randomToken(prefix string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// CreateKey generates and stores an application API key (send-only). The
// plaintext is only available from this call.
func CreateKey(ctx context.Context, repo *storage.Repository, name string) (id int64, plaintext string, err error) {
	if strings.TrimSpace(name) == "" {
		return 0, "", errors.New("key name is required")
	}
	plaintext, hash, err := GenerateKey()
	if err != nil {
		return 0, "", err
	}
	id, err = repo.CreateKey(ctx, name, "write", hash, time.Now().UnixMilli())
	return id, plaintext, err
}

// Authenticator validates API keys and sessions against the database.
type Authenticator struct {
	repo    *storage.Repository
	log     *slog.Logger
	limiter *loginLimiter
}

// New returns an Authenticator.
func New(repo *storage.Repository, log *slog.Logger) *Authenticator {
	if log == nil {
		log = slog.Default()
	}
	return &Authenticator{repo: repo, log: log, limiter: newLoginLimiter()}
}

// Authenticate identifies the caller. A bearer API key is used if an
// Authorization header is present; otherwise the session cookie. It returns
// ErrMissing or ErrInvalid for client errors, any other error is internal.
func (a *Authenticator) Authenticate(r *http.Request) (*Principal, error) {
	if h := r.Header.Get("Authorization"); h != "" {
		scheme, token, ok := strings.Cut(h, " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" {
			return nil, ErrInvalid
		}
		key, err := a.repo.FindActiveKey(r.Context(), hashToken(strings.TrimSpace(token)))
		if errors.Is(err, storage.ErrKeyNotFound) {
			return nil, ErrInvalid
		}
		if err != nil {
			return nil, err
		}
		return &Principal{Kind: KindKey, Name: key.Name}, nil
	}

	c, err := r.Cookie(CookieName)
	if err != nil || c.Value == "" {
		return nil, ErrMissing
	}
	u, err := a.repo.FindSession(r.Context(), hashToken(c.Value), time.Now().UnixMilli())
	if errors.Is(err, storage.ErrUserNotFound) {
		return nil, ErrInvalid
	}
	if err != nil {
		return nil, err
	}
	return &Principal{Kind: KindUser, Name: u.Username, Role: u.Role}, nil
}

// Require wraps next so only callers holding perm get through.
func (a *Authenticator) Require(perm Permission, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := a.Authenticate(r)
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
		if !p.Can(perm) {
			a.log.Warn("auth forbidden", "path", r.URL.Path, "caller", p.Name, "kind", string(p.Kind))
			msg := fmt.Sprintf("%s %q is not allowed to do this", p.Kind, p.Name)
			if p.Kind == KindKey {
				msg = fmt.Sprintf("API key %q can only send logs; sign in with a user account to search", p.Name)
			}
			deny(w, http.StatusForbidden, msg)
			return
		}
		// Cookies are sent by browsers automatically, so for state-changing
		// requests confirm they come from this site (SameSite=Strict already
		// blocks cross-site cookies; this is defense in depth).
		if p.Kind == KindUser && r.Method != http.MethodGet && r.Method != http.MethodHead {
			if o := r.Header.Get("Origin"); o != "" && o != "https://"+r.Host {
				deny(w, http.StatusForbidden, "cross-origin request refused")
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, p)))
	})
}

func deny(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
