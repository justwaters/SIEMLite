package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"siemlite/pkg/audit"
	"siemlite/pkg/auth"
)

// The System page's IP locations panel: SIEMLite downloads the free DB-IP location data
// itself (see pkg/geoipdb) unless the operator gave their own files.

// geoipSource is "dbip", "own" or "none", for the page's address tooltips.
func (s *Server) geoipSource() string {
	if s.deps.GeoIP == nil {
		return "none"
	}
	return s.deps.GeoIP.Status(context.Background()).Source
}

func (s *Server) handleGetGeoIP(w http.ResponseWriter, r *http.Request) {
	if s.deps.GeoIP == nil {
		writeError(w, http.StatusNotImplemented, "this server can't download IP location data")
		return
	}
	writeJSON(w, http.StatusOK, s.deps.GeoIP.Status(r.Context()))
}

func (s *Server) handleSaveGeoIP(w http.ResponseWriter, r *http.Request) {
	if s.deps.GeoIP == nil {
		writeError(w, http.StatusNotImplemented, "this server can't download IP location data")
		return
	}
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if !decodeJSON(w, r, &req, 1<<10) {
		return
	}
	if req.Enabled == nil {
		writeError(w, http.StatusBadRequest, "Say whether to download IP location data.")
		return
	}
	was := s.deps.GeoIP.Enabled(r.Context())
	if err := s.deps.GeoIP.SetEnabled(r.Context(), *req.Enabled); err != nil {
		s.internal(w, "save the IP locations setting", err)
		return
	}
	if *req.Enabled != was {
		who := auth.FromContext(r.Context()).Name
		word := map[bool]string{true: "on", false: "off"}[*req.Enabled]
		s.deps.Logger.Info("IP location download changed", "to", word, "by", who)
		s.audit(r, audit.Entry{Action: "system.geoip", Severity: 2, Message: fmt.Sprintf("%s turned downloading IP location data %s", who, word)})
		if *req.Enabled {
			go s.deps.GeoIP.Check(context.Background())
		}
	}
	writeJSON(w, http.StatusOK, s.deps.GeoIP.Status(r.Context()))
}

// handleCheckGeoIP looks for a newer edition now and answers when done (a first download
// takes a minute or so).
func (s *Server) handleCheckGeoIP(w http.ResponseWriter, r *http.Request) {
	if s.deps.GeoIP == nil {
		writeError(w, http.StatusNotImplemented, "this server can't download IP location data")
		return
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(20 * time.Minute))
	writeJSON(w, http.StatusOK, s.deps.GeoIP.Check(r.Context()))
}
