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
	"sync"
	"sync/atomic"
	"time"

	"siemlite/pkg/storage"
)

// Permission is something a caller may do.
type Permission int

const (
	PermIngest Permission = iota + 1 // send events and logs
	PermSearch                       // search and read health details
	PermAdmin                        // manage users, sources and parsers
)

// Kind says how a caller authenticated.
type Kind string

const (
	KindKey   Kind = "key"
	KindUser  Kind = "user"
	KindAgent Kind = "agent" // an AI agent on the MCP endpoint (never on the REST API)
)

// User roles.
const (
	RoleAdmin    = "admin"    // everything
	RoleStandard = "standard" // search, optionally limited to some sources
)

// KeyPrefix makes keys recognizable to secret scanners.
const KeyPrefix = "slk_"

// AgentKeyPrefix does the same for AI agent tokens.
const AgentKeyPrefix = "slmcp_"

var (
	ErrMissing = errors.New("authentication required")
	ErrInvalid = errors.New("invalid or revoked API key, or expired session")
)

// Principal is an authenticated caller.
type Principal struct {
	Kind Kind
	Name string
	Role string // users only
	// UserID is set for users; SourceID for access tokens.
	UserID   int64
	SourceID int64
	// Limited users see only events from Sources, which may be empty (then
	// they see nothing). The limit is an explicit flag, never inferred from
	// the list, so a missing list can't widen access.
	Limited bool
	Sources []int64
	// AuthProvider is how a user signs in: storage.ProviderLocal (a password
	// here) or a service such as Microsoft Entra.
	AuthProvider string
	// DisplayName is the name to show (a Microsoft account's display name),
	// or empty; Name stays the unique account name.
	DisplayName string
}

// Label is how the person is named in messages: "Justin Waters
// (justin@fisni.com)" when they have a display name, else the account name.
func (p *Principal) Label() string {
	if p.DisplayName == "" || p.DisplayName == p.Name {
		return p.Name
	}
	return p.DisplayName + " (" + p.Name + ")"
}

// Restricted reports whether the caller may only see some sources.
func (p *Principal) Restricted() bool {
	return p.Kind == KindUser && p.Role != RoleAdmin && p.Limited
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
		case RoleStandard:
			return perm == PermSearch
		}
	case KindAgent: // Role holds the token's level
		switch p.Role {
		case storage.AgentAdmin:
			return perm == PermSearch || perm == PermAdmin
		case storage.AgentRead, storage.AgentAnalyst:
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

// NewContext returns ctx carrying p as the authenticated caller, as Require
// does, for code that runs a handler on a caller's behalf.
func NewContext(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// GenerateAgentKey returns a new random AI agent token and its storage hash.
func GenerateAgentKey() (plaintext, hash string, err error) {
	plaintext, err = randomToken(AgentKeyPrefix)
	if err != nil {
		return "", "", err
	}
	return plaintext, hashToken(plaintext), nil
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

// CreateKey creates an access token source (send-only) with an optional
// parser, or with parserNone to keep its lines as they arrive. The plaintext
// token is only available from this call.
func CreateKey(ctx context.Context, repo *storage.Repository, name string, parserID *int64, parserNone bool) (id int64, plaintext string, err error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 80 {
		return 0, "", errors.New("source name must be 1-80 characters")
	}
	plaintext, hash, err := GenerateKey()
	if err != nil {
		return 0, "", err
	}
	id, err = repo.CreateTokenSource(ctx, name, hash, parserID, parserNone, time.Now().UnixMilli())
	return id, plaintext, err
}

// RotateKey gives an access token source a new key and returns it. The old
// key stops working at once; the plaintext is only available from this call.
func RotateKey(ctx context.Context, repo *storage.Repository, id int64) (plaintext string, err error) {
	plaintext, hash, err := GenerateKey()
	if err != nil {
		return "", err
	}
	if err := repo.ReplaceTokenKey(ctx, id, hash); err != nil {
		return "", err
	}
	return plaintext, nil
}

// Authenticator validates API keys and sessions against the database.
type Authenticator struct {
	repo     *storage.Repository
	log      *slog.Logger
	limiter  *loginLimiter // failed sign-ins per client address
	accounts *loginLimiter // failed sign-ins per account, from anywhere
	changes  *loginLimiter // wrong current passwords per account, when changing one's own
	policy   atomic.Pointer[Policy]

	// lastTouch throttles "last used" writes to one per source per minute.
	touchMu   sync.Mutex
	lastTouch map[int64]time.Time
}

// New returns an Authenticator.
func New(repo *storage.Repository, log *slog.Logger) *Authenticator {
	if log == nil {
		log = slog.Default()
	}
	return &Authenticator{repo: repo, log: log, limiter: newLoginLimiter(maxFailures), accounts: newLoginLimiter(maxAccountFailures),
		changes: newLoginLimiter(maxFailures), lastTouch: map[int64]time.Time{}}
}

// AttemptsAllowed reports whether a client address may try to sign in (it is
// locked out after repeated failures). Single sign-on shares this with passwords.
func (a *Authenticator) AttemptsAllowed(remote string) bool { return a.limiter.allow(remote) }

// RecordFailure counts a failed sign-in against a client address.
func (a *Authenticator) RecordFailure(remote string) { a.limiter.fail(remote) }

// TouchSource records that a source sent logs, at most once a minute per
// source so busy senders don't turn every request into a write.
func (a *Authenticator) TouchSource(ctx context.Context, id int64) {
	now := time.Now()
	a.touchMu.Lock()
	if now.Sub(a.lastTouch[id]) < time.Minute {
		a.touchMu.Unlock()
		return
	}
	a.lastTouch[id] = now
	a.touchMu.Unlock()
	if err := a.repo.TouchSource(ctx, id, now.UnixMilli()); err != nil {
		a.log.Warn("recording source use failed", "source", id, "err", err)
	}
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
		src, err := a.repo.FindActiveToken(r.Context(), hashToken(strings.TrimSpace(token)))
		if errors.Is(err, storage.ErrSourceNotFound) {
			return nil, ErrInvalid
		}
		if err != nil {
			return nil, err
		}
		return &Principal{Kind: KindKey, Name: src.Name, SourceID: src.ID}, nil
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
	if !a.sessionAllowed(r.Context(), u.Username, u.AuthProvider) {
		return nil, ErrInvalid
	}
	return &Principal{Kind: KindUser, Name: u.Username, Role: u.Role, UserID: u.ID, Limited: u.Limited, Sources: u.Sources, AuthProvider: u.AuthProvider, DisplayName: u.DisplayName}, nil
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
		if p.Kind == KindUser && r.Method != http.MethodGet && r.Method != http.MethodHead && CrossSite(r) {
			deny(w, http.StatusForbidden, "cross-origin request refused")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, p)))
	})
}

// CrossSite reports whether a browser sent r from another site. Browsers
// send Origin on every cross-origin request that can change state, and
// Sec-Fetch-Site on every request, so a request is refused when either says
// it came from elsewhere. A request with neither (a command-line tool, or an
// old browser) is allowed: it carries no cookie the site set with SameSite.
func CrossSite(r *http.Request) bool {
	if o := r.Header.Get("Origin"); o != "" && o != "https://"+r.Host {
		return true
	}
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "same-origin", "none":
		return false
	}
	return true
}

func deny(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
