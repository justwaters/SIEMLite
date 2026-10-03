package auth

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"siemlite/pkg/storage"
)

const (
	// CookieName is the session cookie.
	CookieName = "siemlite_session"
	// SessionTTL is how long a sign-in lasts.
	SessionTTL = 12 * time.Hour

	// MinPasswordLen and maxPasswordLen bound passwords; bcrypt ignores
	// anything past 72 bytes, so longer ones are refused rather than truncated.
	MinPasswordLen = 12
	maxPasswordLen = 72
)

// HashCost is the bcrypt cost. Tests lower it.
var HashCost = 12

var ErrBadCredentials = errors.New("invalid username or password")

// ParseUserRole validates a user role name. "analyst", the old name for a
// standard user, is still accepted.
func ParseUserRole(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case RoleAdmin:
		return RoleAdmin, nil
	case RoleStandard, "analyst":
		return RoleStandard, nil
	}
	return "", fmt.Errorf("role must be admin or standard (got %q)", s)
}

// ValidatePassword enforces the password policy.
func ValidatePassword(pw string) error {
	if len(pw) < MinPasswordLen {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLen)
	}
	if len(pw) > maxPasswordLen {
		return fmt.Errorf("password must be at most %d bytes", maxPasswordLen)
	}
	return nil
}

// CreateUser validates and stores a new user.
func CreateUser(ctx context.Context, repo *storage.Repository, username, password, role string) (int64, error) {
	username = strings.TrimSpace(username)
	if username == "" || len(username) > 64 {
		return 0, errors.New("username must be 1-64 characters")
	}
	role, err := ParseUserRole(role)
	if err != nil {
		return 0, err
	}
	if err := ValidatePassword(password); err != nil {
		return 0, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), HashCost)
	if err != nil {
		return 0, fmt.Errorf("hash password: %w", err)
	}
	return repo.CreateUser(ctx, username, string(hash), role, time.Now().UnixMilli())
}

// SetPassword changes a user's password and ends their sessions.
func SetPassword(ctx context.Context, repo *storage.Repository, username, password string) error {
	if err := ValidatePassword(password); err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), HashCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	ok, err := repo.SetPassword(ctx, username, string(hash))
	if err != nil {
		return err
	}
	if !ok {
		return storage.ErrUserNotFound
	}
	return nil
}

// GeneratePassword returns a random password for bootstrap accounts.
func GeneratePassword() (string, error) {
	const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b), nil
}

// dummyHash lets Login spend the same time on unknown usernames as on known
// ones, so response timing does not reveal which usernames exist.
var (
	dummyOnce sync.Once
	dummyHash []byte
)

func spendHashTime(password string) {
	dummyOnce.Do(func() { dummyHash, _ = bcrypt.GenerateFromPassword([]byte("dummy-password"), HashCost) })
	_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
}

// Login checks credentials and starts a session. remote is the caller's
// address, used only to rate-limit failed attempts. The returned token goes in
// the session cookie.
func (a *Authenticator) Login(ctx context.Context, remote, username, password string) (token string, user *storage.User, err error) {
	if !a.limiter.allow(remote) {
		return "", nil, ErrTooManyAttempts
	}
	u, hash, err := a.repo.GetUserForLogin(ctx, strings.TrimSpace(username))
	switch {
	case errors.Is(err, storage.ErrUserNotFound):
		spendHashTime(password)
		a.limiter.fail(remote)
		a.log.Warn("login failed", "remote", remote, "user", username)
		return "", nil, ErrBadCredentials
	case err != nil:
		return "", nil, err
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		a.limiter.fail(remote)
		a.log.Warn("login failed", "remote", remote, "user", username)
		return "", nil, ErrBadCredentials
	}
	a.limiter.reset(remote)

	token, err = randomToken("")
	if err != nil {
		return "", nil, err
	}
	now := time.Now()
	if err := a.repo.PurgeExpiredSessions(ctx, now.UnixMilli()); err != nil {
		a.log.Warn("purge sessions failed", "err", err)
	}
	if err := a.repo.CreateSession(ctx, hashToken(token), u.ID, now.UnixMilli(), now.Add(SessionTTL).UnixMilli()); err != nil {
		return "", nil, err
	}
	a.log.Info("login", "user", u.Username, "remote", remote)
	return token, u, nil
}

// Logout ends the session for the request's cookie, if any.
func (a *Authenticator) Logout(r *http.Request) error {
	c, err := r.Cookie(CookieName)
	if err != nil || c.Value == "" {
		return nil
	}
	return a.repo.DeleteSession(r.Context(), hashToken(c.Value))
}

// SetSessionCookie writes the session cookie. It is HttpOnly (no script
// access), Secure (HTTPS only) and SameSite=Strict (never sent cross-site).
func SetSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: token, Path: "/",
		Expires: time.Now().Add(SessionTTL), MaxAge: int(SessionTTL.Seconds()),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
}

// ClearSessionCookie expires the session cookie.
func ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
}

// ErrTooManyAttempts is returned while a client is locked out.
var ErrTooManyAttempts = errors.New("too many failed sign-in attempts; try again later")

// loginLimiter blocks a client address after repeated failed sign-ins.
type loginLimiter struct {
	mu      sync.Mutex
	entries map[string]*attempts
}

type attempts struct {
	count int
	first time.Time
}

const (
	maxFailures   = 10
	failureWindow = 15 * time.Minute
)

func newLoginLimiter() *loginLimiter { return &loginLimiter{entries: map[string]*attempts{}} }

func (l *loginLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[key]
	if !ok {
		return true
	}
	if time.Since(e.first) > failureWindow {
		delete(l.entries, key)
		return true
	}
	return e.count < maxFailures
}

func (l *loginLimiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[key]
	if !ok || time.Since(e.first) > failureWindow {
		l.entries[key] = &attempts{count: 1, first: time.Now()}
		return
	}
	e.count++
}

func (l *loginLimiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}
