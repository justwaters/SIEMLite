package api

import (
	"fmt"
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
	s.flushSignin() // what the timer does when the minute ends
	if s.signinDropped != 0 {
		t.Errorf("after the minute: %d still waiting to be counted", s.signinDropped)
	}
	s.signinWindow = s.signinWindow.Add(-time.Minute) // the next minute starts
	s.auditSignin(r, audit.Entry{Action: "signin.failed"})
	if s.signinCount != 1 {
		t.Errorf("new minute: recorded %d", s.signinCount)
	}

	if !s.firstBlock("192.0.2.1") || s.firstBlock("192.0.2.1") || !s.firstBlock("192.0.2.2") {
		t.Error("a lockout should be recorded once per address")
	}
	s.signinBlocked["192.0.2.1"] = time.Now().Add(-signinBlockedEvery)
	if !s.firstBlock("192.0.2.1") {
		t.Error("a new lockout after the window should be recorded")
	}
	// The list of addresses stays bounded; beyond it blocks are recorded.
	for i := 0; i < signinBlockedMax+10; i++ {
		s.firstBlock(fmt.Sprintf("2001:db8::%x", i))
	}
	if len(s.signinBlocked) > signinBlockedMax || !s.firstBlock("2001:db8:1::1") || !s.firstBlock("2001:db8:1::1") {
		t.Errorf("remembered %d addresses; past the limit, blocks should be recorded", len(s.signinBlocked))
	}
}
