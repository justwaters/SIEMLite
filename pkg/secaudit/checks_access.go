package secaudit

import (
	"context"
	"fmt"
)

func accessChecks() []Check {
	return []Check{
		{ID: "access.admin", Category: CatAccess, Title: "The built-in admin account is kept to this server", Severity: Medium, Run: checkAdminLocal},
		{ID: "access.admins", Category: CatAccess, Title: "Few accounts are Admins", Severity: Low, Run: checkAdminCount},
	}
}

func checkAdminLocal(_ context.Context, e *Env) Outcome {
	c := e.Cfg
	switch {
	case !c.BuiltinAdmin:
		return Outcome{Status: Pass, Detail: "There's no active built-in account named admin."}
	case c.AdminLocalOnly:
		return Outcome{Status: Pass, Detail: "The admin account can only sign in on this server's local port."}
	case c.LocalAddr == "":
		return Outcome{Status: Warn, Detail: "The account named admin is a known name with full control and it can sign in with a password from anywhere. This server has no local port to keep it to.",
			Fix: "Start SIEMLite with -local-addr (the default is localhost:8444), then turn on Keep the admin account to this server on the Users page. Or create a personal Admin account and disable admin."}
	}
	return Outcome{Status: Warn, Detail: "The account named admin is a known name with full control and it can sign in with a password from anywhere, so it is the first thing a password-guessing attack tries.",
		Fix: "On the Users page, turn on Keep the admin account to this server, and use named Admin accounts day to day."}
}

func checkAdminCount(_ context.Context, e *Env) Outcome {
	n := e.Cfg.EnabledAdmins
	if n > 3 {
		return Outcome{Status: Warn, Detail: fmt.Sprintf("%d accounts are Admins. Each one can read every log, change every setting and create more Admins.", n),
			Fix: "On the Users page, change accounts that only search logs to Standard."}
	}
	return Outcome{Status: Pass, Detail: fmt.Sprintf("%d accounts are Admins.", n)}
}
