// Package entra signs people in with Microsoft Entra ID (OpenID Connect) and
// keeps who may sign in in step with a group in the organization's directory.
//
// A person signs in at Microsoft, and SIEMLite then asks Microsoft Graph, with
// its own application credentials, whether they are in the access group (and
// the optional admin group). Accounts are created on first sign-in. A
// background sync disables accounts whose owner has left the group.
package entra

import (
	"net/url"
	"regexp"
	"strings"

	"siemlite/pkg/integrations"
)

// InputError is a mistake in what a person entered, worded for them.
type InputError = integrations.InputError

// Provider is this integration's value in users.auth_provider.
const Provider = "entra"

// CallbackPath is where Microsoft sends people back to SIEMLite.
const CallbackPath = "/api/v1/auth/entra/callback"

var guidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// Config is the Entra app and groups, without the client secret.
type Config struct {
	// TenantID is the Directory (tenant) ID, a GUID.
	TenantID string `json:"tenant_id"`
	// ClientID is the app registration's Application (client) ID, a GUID.
	ClientID string `json:"client_id"`
	// PublicURL is the address people use to reach SIEMLite, such as
	// https://siem.example.com:8443. The redirect URL registered in Entra is
	// this plus CallbackPath.
	PublicURL string `json:"public_url"`
	// AccessGroupID is the object ID of the group whose members may sign in.
	AccessGroupID string `json:"access_group_id"`
	// AdminGroupID is optional: its members are Admins, everyone else Standard.
	AdminGroupID string `json:"admin_group_id"`
}

func isGUID(s string) bool { return guidRe.MatchString(s) }

// normalize trims and lowercases what is entered.
func (c Config) normalize() Config {
	c.TenantID = strings.ToLower(strings.TrimSpace(c.TenantID))
	c.ClientID = strings.ToLower(strings.TrimSpace(c.ClientID))
	c.AccessGroupID = strings.ToLower(strings.TrimSpace(c.AccessGroupID))
	c.AdminGroupID = strings.ToLower(strings.TrimSpace(c.AdminGroupID))
	c.PublicURL = strings.TrimRight(strings.TrimSpace(c.PublicURL), "/")
	return c
}

// Validate checks a Config the way a person filling it in would want to be told.
func (c Config) Validate() error {
	c = c.normalize()
	if !isGUID(c.TenantID) {
		return InputError("The tenant ID is the Directory (tenant) ID from the app's Overview page in Entra: a value like 11111111-2222-3333-4444-555555555555.")
	}
	if !isGUID(c.ClientID) {
		return InputError("The client ID is the Application (client) ID from the app's Overview page in Entra: a value like 11111111-2222-3333-4444-555555555555.")
	}
	u, err := url.Parse(c.PublicURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return InputError("The SIEMLite address must be an https address with no path, such as https://siem.example.com:8443.")
	}
	if !isGUID(c.AccessGroupID) {
		return InputError("The access group is the Object ID of a group (a GUID), from the group's Overview page in Entra.")
	}
	if c.AdminGroupID != "" && !isGUID(c.AdminGroupID) {
		return InputError("The admin group is the Object ID of a group (a GUID). Leave it empty to make everyone a Standard user.")
	}
	return nil
}

// RedirectURI is the redirect URL to register in Entra.
func (c Config) RedirectURI() string {
	return strings.TrimRight(strings.TrimSpace(c.PublicURL), "/") + CallbackPath
}

// sameApp reports whether o signs in to the same Entra app, so a client secret
// saved for c is safe to use with it.
func (c Config) sameApp(o Config) bool {
	c, o = c.normalize(), o.normalize()
	return c.TenantID == o.TenantID && c.ClientID == o.ClientID
}
