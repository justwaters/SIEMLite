package auth

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"strconv"
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

var ErrBadCredentials = errors.New("invalid username or password, or the account is temporarily locked after too many attempts")

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

// GeneratePassword returns a random password for bootstrap accounts. Each
// character is drawn uniformly (a byte modulo the alphabet's size would favor
// its first characters).
func GeneratePassword() (string, error) {
	const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	out := make([]byte, 0, 20)
	for len(out) < cap(out) {
		var b [1]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", err
		}
		// 256 isn't a multiple of 57; bytes past the largest one are redrawn.
		if int(b[0]) >= 256-256%len(alphabet) {
			continue
		}
		out = append(out, alphabet[int(b[0])%len(alphabet)])
	}
	return string(out), nil
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
//
// Failed attempts are counted per address and, more loosely, per account, so
// an attacker spreading guesses over many addresses is still slowed. What was
// typed as the username is logged only when it names an account: people
// sometimes type their password into the username field.
func (a *Authenticator) Login(ctx context.Context, remote, username, password string) (token string, user *storage.User, err error) {
	username = strings.TrimSpace(username)
	account := strings.ToLower(username)
	if err := a.passwordAllowed(ctx, username); err != nil {
		return "", nil, err
	}
	// Each attempt is counted before it is checked, in one step, so guesses sent
	// in parallel can't all pass the limit before the first failure is recorded.
	if !a.limiter.take(remote) {
		return "", nil, ErrTooManyAttempts
	}
	u, hash, err := a.repo.GetUserForLogin(ctx, username)
	switch {
	case errors.Is(err, storage.ErrUserNotFound):
		spendHashTime(password)
		a.log.Warn("login failed", "remote", remote, "user", "(unknown username)")
		return "", nil, ErrBadCredentials
	case err != nil:
		return "", nil, err
	}
	// Only real accounts are counted per account: counting made-up names would
	// let a flood of them push a real account's entry out of the table.
	// At the account's limit the answer and the time taken match an unknown
	// name's, so the limit can't be used to tell which names are accounts.
	if !a.accounts.take(account) {
		spendHashTime(password)
		a.log.Warn("login refused: too many attempts for the account", "remote", remote, "user", u.Username)
		return "", nil, ErrBadCredentials
	}
	// Accounts that sign in through a service, and disabled accounts, never
	// sign in with a password. This looks the same as a wrong password.
	if u.AuthProvider != storage.ProviderLocal || u.Disabled {
		spendHashTime(password)
		a.log.Warn("login failed", "remote", remote, "user", u.Username)
		return "", nil, ErrBadCredentials
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		a.log.Warn("login failed", "remote", remote, "user", u.Username)
		return "", nil, ErrBadCredentials
	}
	a.limiter.reset(remote)
	a.accounts.reset(account)

	if token, err = a.StartSession(ctx, u); err != nil {
		return "", nil, err
	}
	a.log.Info("login", "user", u.Username, "remote", remote)
	return token, u, nil
}

// ErrWrongPassword means the current password given to ChangeOwnPassword is wrong.
var ErrWrongPassword = errors.New("The current password is wrong.")

// ErrNoPassword means the account signs in elsewhere (such as Microsoft) and has no password here.
var ErrNoPassword = errors.New("This account signs in with Microsoft, so its password is managed by your organization.")

// PasswordError is a new password that can't be used. Its message is meant
// for the person choosing it.
type PasswordError struct{ msg string }

func (e PasswordError) Error() string { return e.msg }

// ChangeOwnPassword lets a signed-in user change their password: the current
// one must be right. Wrong guesses are limited per account, separately from
// signing in, so a session can't be used to lock its owner out of signing in
// and failed sign-ins don't stop the owner changing their password. The new
// password is stored, every session of the account ends and a new one starts
// for the caller in one step; the caller's cookie should be set to the
// returned token.
func (a *Authenticator) ChangeOwnPassword(ctx context.Context, remote string, userID int64, current, next string) (token string, err error) {
	u, hash, err := a.repo.GetUserWithHash(ctx, userID)
	if errors.Is(err, storage.ErrUserNotFound) {
		return "", ErrInvalid
	}
	if err != nil {
		return "", err
	}
	if u.AuthProvider != storage.ProviderLocal {
		return "", ErrNoPassword
	}
	if err := ValidatePassword(next); err != nil {
		return "", PasswordError{err.Error()}
	}
	if current == next {
		return "", PasswordError{"Choose a password different from the current one."}
	}
	// Each attempt counts until it succeeds, so concurrent guesses can't slip
	// past the limit while bcrypt runs.
	key := strconv.FormatInt(userID, 10)
	if !a.changes.take(key) {
		return "", ErrTooManyAttempts
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(current)) != nil {
		a.log.Warn("password change refused: wrong current password", "user", u.Username, "remote", remote)
		return "", ErrWrongPassword
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(next), HashCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	if token, err = randomToken(""); err != nil {
		return "", err
	}
	now := time.Now()
	err = a.repo.ChangeOwnPassword(ctx, userID, string(newHash), hashToken(token), now.UnixMilli(), now.Add(SessionTTL).UnixMilli())
	switch {
	case errors.Is(err, storage.ErrExternalUser):
		return "", ErrNoPassword
	case errors.Is(err, storage.ErrUserNotFound):
		return "", ErrInvalid
	case err != nil:
		return "", err
	}
	a.changes.reset(key)
	a.log.Info("password changed by its owner", "user", u.Username, "remote", remote)
	return token, nil
}

// StartSession begins a session for a user who has already been verified, by
// password in Login or by single sign-on, and returns the cookie's token. It
// refuses a disabled account.
func (a *Authenticator) StartSession(ctx context.Context, u *storage.User) (string, error) {
	if u.Disabled {
		return "", ErrBadCredentials
	}
	token, err := randomToken("")
	if err != nil {
		return "", err
	}
	now := time.Now()
	if err := a.repo.PurgeExpiredSessions(ctx, now.UnixMilli()); err != nil {
		a.log.Warn("purge sessions failed", "err", err)
	}
	if err := a.repo.CreateSession(ctx, hashToken(token), u.ID, now.UnixMilli(), now.Add(SessionTTL).UnixMilli()); err != nil {
		return "", err
	}
	return token, nil
}

// EndSession ends one session by its cookie token.
func (a *Authenticator) EndSession(ctx context.Context, token string) error {
	return a.repo.DeleteSession(ctx, hashToken(token))
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

// loginLimiter blocks a key (a client address, or an account name) after
// repeated failed sign-ins. It remembers at most maxEntries keys: past that,
// expired entries are dropped and then, if still full, one at random, so a
// flood of failures from ever-changing addresses can't grow it without bound.
type loginLimiter struct {
	max int // failures allowed in a window

	mu      sync.Mutex
	entries map[string]*attempts
}

type attempts struct {
	count int
	first time.Time
}

const (
	// maxFailures is per address. An account is locked only after many more,
	// from any number of addresses, so one person can't shut a colleague out
	// with a few wrong guesses, while spraying across addresses is still slowed.
	maxFailures        = 10
	maxAccountFailures = 50
	failureWindow      = 15 * time.Minute
	maxEntries         = 100_000
)

func newLoginLimiter(max int) *loginLimiter {
	return &loginLimiter{max: max, entries: map[string]*attempts{}}
}

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
	return e.count < l.max
}

// take counts an attempt before it is made and reports whether it may go
// ahead; reset forgives them once one succeeds.
func (l *loginLimiter) take(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	e, ok := l.entries[key]
	if ok && now.Sub(e.first) <= failureWindow {
		if e.count >= l.max {
			return false
		}
		e.count++
		return true
	}
	if !ok && len(l.entries) >= maxEntries {
		l.makeRoom(now)
	}
	l.entries[key] = &attempts{count: 1, first: now}
	return true
}

func (l *loginLimiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	e, ok := l.entries[key]
	if ok && now.Sub(e.first) <= failureWindow {
		e.count++
		return
	}
	if !ok && len(l.entries) >= maxEntries {
		l.makeRoom(now)
	}
	l.entries[key] = &attempts{count: 1, first: now}
}

// makeRoom frees at least one entry: every expired one, else any one.
func (l *loginLimiter) makeRoom(now time.Time) {
	for k, e := range l.entries {
		if now.Sub(e.first) > failureWindow {
			delete(l.entries, k)
		}
	}
	if len(l.entries) < maxEntries {
		return
	}
	for k := range l.entries {
		delete(l.entries, k)
		return
	}
}

// size is how many keys are remembered (for tests).
func (l *loginLimiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

func (l *loginLimiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}
