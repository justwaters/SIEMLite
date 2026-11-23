package api

import (
	"net/http"
	"net/netip"
	"strings"

	"siemlite/pkg/audit"
	"siemlite/pkg/auth"
	"siemlite/pkg/syslogd"
)

// SyslogAllowSetting is the setting that holds the allowlist saved from the
// Syslog source's Manage dialog. When set it replaces -syslog-allow.
const SyslogAllowSetting = "syslog_allow"

const maxSyslogAllow = 500

type syslogAllowView struct {
	Allow     []string `json:"allow"`     // networks allowed to send, as CIDRs
	Default   bool     `json:"default"`   // true when no list is saved: loopback and private ranges
	Listening bool     `json:"listening"` // false when no syslog listener is running
	Denied    uint64   `json:"denied"`    // messages refused since start
}

func prefixStrings(ps []netip.Prefix) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return out
}

func (s *Server) syslogAllowView(r *http.Request) syslogAllowView {
	saved, _ := s.deps.Repo.Setting(r.Context(), SyslogAllowSetting, "")
	v := syslogAllowView{Default: strings.TrimSpace(saved) == ""}
	if sv := s.deps.Syslog; sv != nil {
		v.Listening = true
		v.Allow = prefixStrings(sv.Allow())
		v.Denied = sv.Stats().Denied
		// A list from -syslog-allow is not "the default" either.
		v.Default = v.Default && prefixesEqual(sv.Allow(), syslogd.DefaultAllow)
		return v
	}
	ps, _ := syslogd.ParseAllow(saved)
	if len(ps) == 0 {
		ps = syslogd.DefaultAllow
	}
	v.Allow = prefixStrings(ps)
	return v
}

func prefixesEqual(a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (s *Server) handleGetSyslogAllow(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.syslogAllowView(r))
}

// handleSetSyslogAllow saves the allowlist and applies it to the running
// listener at once. An empty list restores the default (loopback and
// private ranges).
func (s *Server) handleSetSyslogAllow(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Allow []string `json:"allow"`
	}
	if !decodeJSON(w, r, &in, 64<<10) {
		return
	}
	if len(in.Allow) > maxSyslogAllow {
		writeError(w, http.StatusBadRequest, "too many entries (the limit is 500)")
		return
	}
	prefixes, err := syslogd.ParseAllow(strings.Join(in.Allow, "\n"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	value := strings.Join(prefixStrings(prefixes), ",")
	if err := s.deps.Repo.SetSetting(r.Context(), SyslogAllowSetting, value); err != nil {
		s.deps.Logger.Error("save syslog allowlist", "err", err)
		writeError(w, http.StatusInternalServerError, "could not save the list")
		return
	}
	if s.deps.Syslog != nil {
		s.deps.Syslog.SetAllow(prefixes)
	}
	msg := auth.FromContext(r.Context()).Name + " set the syslog allowlist to "
	if len(prefixes) == 0 {
		msg += "the default (loopback and private networks)"
	} else {
		msg += strings.Join(prefixStrings(prefixes), ", ")
	}
	s.audit(r, audit.Entry{Action: "syslog.allow", Message: msg, Fields: map[string]string{"allow": value}})
	writeJSON(w, http.StatusOK, s.syslogAllowView(r))
}
