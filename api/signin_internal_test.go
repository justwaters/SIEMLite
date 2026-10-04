package api

import (
	"net/http/httptest"
	"testing"
	"time"

	"siemlite/pkg/audit"
)

func TestSigninAuditLimits(t *testing.T) {
	s := &Server{}
	r := httptest.NewRequest("POST", "/api/v1/login", nil)
	for i := 0; i < signinAuditsPerMinute+100; i++ {
		s.auditSignin(r, audit.Entry{Action: "signin.failed"})
	}
	if s.signinCount != signinAuditsPerMinute || s.signinDropped != 100 {
		t.Errorf("recorded %d, dropped %d", s.signinCount, s.signinDropped)
	}
	s.signinWindow = s.signinWindow.Add(-time.Minute) // the next minute starts
	s.auditSignin(r, audit.Entry{Action: "signin.failed"})
	if s.signinCount != 1 || s.signinDropped != 0 {
		t.Errorf("new minute: recorded %d, dropped %d", s.signinCount, s.signinDropped)
	}

	if !s.firstBlock("192.0.2.1") || s.firstBlock("192.0.2.1") || !s.firstBlock("192.0.2.2") {
		t.Error("a lockout should be recorded once per address")
	}
	s.signinBlocked["192.0.2.1"] = time.Now().Add(-signinBlockedEvery)
	if !s.firstBlock("192.0.2.1") {
		t.Error("a new lockout after the window should be recorded")
	}
}
