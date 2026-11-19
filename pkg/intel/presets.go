package intel

// Preset is a free blocklist SIEMLite knows how to use. An admin turns it on
// from the Threat feeds card; nothing is downloaded until they do.
type Preset struct {
	ID          string `json:"id"`
	Name        string `json:"name"` // also the indicator source a match is credited to
	Description string `json:"description"`
	URL         string `json:"-"`
	Terms       string `json:"terms"`   // where the provider states its terms
	License     string `json:"license"` // what the provider says, in a few words
	Label       string `json:"-"`       // what a match says about the address, e.g. "Tor exit node"
	Category    string `json:"category"`
	Confidence  string `json:"confidence"` // high, medium or low
}

// Presets are the feeds on offer: plain lists of IP addresses that need no
// account or key. Whether a feed may be used in a given business is the
// installer's call, so each carries a link to the provider's own terms.
var Presets = []Preset{
	{ID: "feodo", Category: "Botnet C2", Confidence: "high", Name: "Feodo Tracker", Label: "Botnet command and control server", URL: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
		Description: "Servers that run botnet command and control (Emotet, QakBot and similar). Short and very reliable.",
		Terms:       "https://feodotracker.abuse.ch/blocklist/", License: "Free to use; see abuse.ch"},
	{ID: "c2intel", Category: "C2 server", Confidence: "medium", Name: "C2IntelFeeds (30 days)", Label: "Command and control server", URL: "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv",
		Description: "Command and control servers seen in the last 30 days, such as Cobalt Strike team servers.",
		Terms:       "https://github.com/drb-ra/C2IntelFeeds", License: "No licence stated; check with the author"},
	{ID: "tor-exit", Category: "Anonymizer (Tor exit node)", Confidence: "high", Name: "Tor exit nodes", URL: "https://check.torproject.org/torbulkexitlist", Label: "Tor exit node",
		Description: "Addresses Tor traffic leaves from. Not malicious by itself, but it means someone is hiding where they come from, so every hit is flagged as a threat (a High alert).",
		Terms:       "https://check.torproject.org/", License: "Published by the Tor Project as a public list"},
	{ID: "ipsum3", Category: "Aggregated blocklists", Confidence: "medium", Name: "IPsum (on 3+ lists)", Label: "Listed by 3 or more public blocklists", URL: "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
		Description: "Addresses that at least three separate public blocklists agree on. Broad, with few false alarms.",
		Terms:       "https://github.com/stamparm/ipsum", License: "Unlicense (public domain)"},
	{ID: "blocklistde-strong", Category: "Attacker (brute force, scanning)", Confidence: "medium", Name: "Blocklist.de (strong)", Label: "Reported attacking many Blocklist.de users", URL: "https://lists.blocklist.de/lists/strongips.txt",
		Description: "Addresses that attacked many Blocklist.de users, over a long time.",
		Terms:       "https://www.blocklist.de/en/export.html", License: "Free to use; see blocklist.de"},
	{ID: "blocklistde-brute", Category: "Attacker (login brute force)", Confidence: "medium", Name: "Blocklist.de (login attacks)", Label: "Reported guessing passwords on logins", URL: "https://lists.blocklist.de/lists/bruteforcelogin.txt",
		Description: "Addresses caught guessing passwords on web logins in the last day or so.",
		Terms:       "https://www.blocklist.de/en/export.html", License: "Free to use; see blocklist.de"},
}

// PresetByID finds a preset.
func PresetByID(id string) (Preset, bool) {
	for _, p := range Presets {
		if p.ID == id {
			return p, true
		}
	}
	return Preset{}, false
}
