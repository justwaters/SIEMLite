package secaudit

import "time"

// Config is what the SIEMLite checks know about this installation, filled in
// by the server just before a run: its flags and a few facts from the
// database. It holds plain values so the checks can be tested without a
// server.
type Config struct {
	Version string

	// Paths. Empty means the thing doesn't exist on this installation.
	DBPath        string
	SecretKeyPath string
	TLSKeyPath    string
	BackupDir     string
	ACMEDir       string // Let's Encrypt's account and certificate keys

	// Listen addresses, as given to the flags ("" is off).
	Addr        string // HTTPS
	LocalAddr   string // the local port
	HTTPAddr    string // plain HTTP for a reverse proxy
	SyslogUDP   string
	SyslogTCP   string
	SyslogTLS   string
	SyslogAllow []string // the -syslog-allow networks; empty means loopback and private ranges only

	// TrustedProxies is whether any reverse proxy is trusted.
	TrustedProxies bool

	CertNotAfter   time.Time // zero when unknown
	CertSelfSigned bool

	// BuiltinAdmin is whether the built-in admin account exists and is on;
	// AdminLocalOnly whether it is kept to the server's local port.
	BuiltinAdmin   bool
	AdminLocalOnly bool
	EnabledAdmins  int

	BackupIntervalHours int       // 0 = automatic backups are off
	LastBackup          time.Time // zero when there is none

	UpdateChecks    bool // update checks are on
	UpdateAvailable bool
	LatestVersion   string
}
