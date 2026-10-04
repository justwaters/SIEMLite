package parser

// Templates are ready-made parsers to start from on the Parsers page.
var Templates = []Definition{
	{
		Name:        "Web server access log",
		Description: "nginx and Apache combined log format: client IP, user, time, request, status, size, referrer and browser.",
		Format:      FormatPattern,
		Pattern:     `{src_ip} {_} {user} [{time}] "{method} {path} {protocol}" {status} {bytes} "{referrer}" "{user_agent}"`,
		StripSyslog: true,
		Category:    4,
		Severity: SeverityRule{From: "field", Field: "status", Rules: []SeverityCase{
			{Match: `^5`, Severity: 4},
			{Match: `^(401|403)$`, Severity: 3},
			{Match: `^4`, Severity: 2},
			{Match: `.`, Severity: 1},
		}},
		Samples: []string{
			`203.0.113.7 - - [03/Oct/2026:10:17:12 +0000] "POST /login HTTP/1.1" 401 512 "-" "curl/8.5"`,
			`10.0.0.41 - alice [03/Oct/2026:10:18:01 +0000] "GET /api/orders HTTP/1.1" 200 2048 "https://shop.example/" "Mozilla/5.0"`,
			`198.51.100.23 - - [03/Oct/2026:10:19:45 +0000] "GET /search?q=%27 HTTP/1.1" 500 128 "-" "sqlmap/1.8"`,
		},
	},
	{
		Name:        "JSON application log",
		Description: "One JSON object per line with fields like time, level, msg and user.",
		Format:      FormatJSON,
		Severity:    SeverityRule{From: "auto"},
		Samples: []string{
			`{"time":"2026-10-03T10:17:12Z","level":"error","msg":"payment failed","user":"bob","client":{"ip":"192.0.2.10"}}`,
			`{"time":"2026-10-03T10:17:20Z","level":"info","msg":"order created","user":"alice","order_id":1042}`,
		},
		Fields: map[string]string{"client.ip": "src_ip"},
	},
	{
		Name:        "Key=value firewall log",
		Description: "Lines of key=value pairs, as many firewalls and appliances send them.",
		Format:      FormatKV,
		StripSyslog: true,
		Category:    4,
		Fields:      map[string]string{"spt": "src_port", "dpt": "dst_port"},
		Severity: SeverityRule{From: "field", Field: "action", Rules: []SeverityCase{
			{Match: `(?i)^(block|deny|drop|reject)`, Severity: 2},
			{Match: `.`, Severity: 1},
		}},
		Samples: []string{
			`action=block proto=tcp src=203.0.113.34 spt=51515 dst=10.0.0.5 dpt=3389 rule="inbound default"`,
			`action=allow proto=udp src=10.0.0.12 spt=40000 dst=10.0.0.53 dpt=53 rule=dns`,
		},
	},
	LogGenerator,
}

// LogGenerator reads the test logs made by loggen (cmd/loggen). SIEMLite sets
// it up with its own source on first start, so there is something to explore
// before real logs arrive.
var LogGenerator = Definition{
	Name:        "Log generator",
	Description: "Test logs from loggen: a small company's firewall, web servers, SSH, VPN, DNS, database, mail and antivirus, with attacks mixed in.",
	Format:      FormatPattern,
	Pattern:     `{time}|{host}|{app}|{level}|{action}|{src_ip}|{src_port}|{dst_ip}|{dst_port}|{user}|{message}`,
	Category:    4,
	Severity: SeverityRule{From: "field", Field: "level", Rules: []SeverityCase{
		{Match: `^critical$`, Severity: 5},
		{Match: `^error$`, Severity: 4},
		{Match: `^warning$`, Severity: 3},
		{Match: `^notice$`, Severity: 2},
		{Match: `.`, Severity: 1},
	}},
	Samples: []string{
		`2026-10-04T13:42:07.123Z|bastion-01|sshd|warning|auth.failure|203.0.113.7|51234|10.0.4.12|22|root|Failed password for root from 203.0.113.7`,
		`2026-10-04T13:42:08.004Z|web-01|nginx|info|http.request|198.51.100.23|40112|10.0.2.10|443|-|GET /cart 200 35058b 10ms "Mozilla/5.0"`,
		`2026-10-04T13:42:09.871Z|ws-017|defender|critical|av.detection|-|-|-|-|erin|Threat detected: Ransom.Lockbit in C:\Users\erin\Downloads\invoice.pdf.exe; quarantine failed`,
	},
}
