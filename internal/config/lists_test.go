package config

import (
	"net/netip"
	"path/filepath"
	"server_torii/internal/action"
	"strings"
	"testing"
)

const listsFixture = `Lists:
  - {name: office, enabled: true, type: ip, file: office.conf, action: allow}
  - {name: bad_networks, enabled: false, type: ip, file: lists/bad.conf, action: block}
  - {name: login, enabled: true, type: url, file: login.conf, action: challenge}
  - {name: partners, enabled: true, type: ip, file: partners.conf}
`

func listsDirectory(t *testing.T, settings string, files map[string]string) string {
	t.Helper()
	dir := siteDirectory(t, settings)
	mustMkdirAll(t, filepath.Join(dir, "lists"))
	writeRuleFiles(t, dir, files)
	return dir
}

var listFiles = map[string]string{
	"office.conf":    "# the office\n192.0.2.0/24\n\n  2001:db8:1::/48  \n::ffff:198.51.100.7\n",
	"lists/bad.conf": "203.0.113.9\n",
	"login.conf":     "/login\n/login?next=/\nregex:^/account/[0-9]+$\n",
	"partners.conf":  "198.51.100.0/24\n",
}

func TestListsLoad(t *testing.T) {
	rules, err := LoadRules(listsDirectory(t, listsFixture, listFiles))
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, l := range rules.Lists.All() {
		order = append(order, l.Name)
	}
	if got := strings.Join(order, " "); got != "office bad_networks login partners" {
		t.Fatalf("order = %s", got)
	}

	addr := netip.MustParseAddr
	office, bad, login, partners := rules.Lists.ByName("office"), rules.Lists.ByName("bad_networks"), rules.Lists.ByName("login"), rules.Lists.ByName("partners")
	for name, holds := range map[string]bool{
		"office is an enabled allow list":    office.Enabled && office.Action == action.ActionAllow && office.Type == ListIP && office.Len() == 3,
		"IPv4 network":                       office.ContainsAddr(addr("192.0.2.200")) && !office.ContainsAddr(addr("192.0.3.1")),
		"IPv6 network":                       office.ContainsAddr(addr("2001:db8:1:2::3")) && !office.ContainsAddr(addr("2001:db8:2::1")),
		"IPv4-mapped entry is an IPv4 entry": office.ContainsAddr(addr("198.51.100.7")) && office.ContainsAddr(addr("::ffff:198.51.100.7")),
		"an IP list holds no URL":            !office.ContainsURL("/login"),
		"a disabled list is loaded":          !bad.Enabled && bad.Action == action.ActionBlock && bad.ContainsAddr(addr("203.0.113.9")),
		"exact URL with and without query":   login.ContainsURL("/login") && login.ContainsURL("/login?next=/") && !login.ContainsURL("/login?next=/x"),
		"regex URL":                          login.ContainsURL("/account/42") && !login.ContainsURL("/account/me"),
		"a URL list holds no address":        !login.ContainsAddr(addr("192.0.2.1")),
		"a list without an action":           partners.Enabled && partners.Action == action.ActionNone,
		"an unknown name":                    rules.Lists.ByName("nope") == nil,
		"allow lists exempt, others do not":  rules.Lists.AllowsAddr(addr("192.0.2.1")) && !rules.Lists.AllowsAddr(addr("198.51.100.1")) && !rules.Lists.AllowsURL("/login"),
	} {
		if !holds {
			t.Errorf("%s: does not hold", name)
		}
	}
}

func TestListsRejects(t *testing.T) {
	one := func(fields string) string { return "Lists:\n  - {" + fields + "}\n" }
	const valid = "name: a, enabled: true, type: ip, file: a.conf"
	for name, tt := range map[string]struct {
		settings string
		files    map[string]string
		want     string
	}{
		"no name":             {one("enabled: true, type: ip, file: a.conf"), nil, "name"},
		"upper-case name":     {one("name: Office, enabled: true, type: ip, file: a.conf"), nil, "lower-case letters"},
		"name with a dash":    {one("name: my-list, enabled: true, type: ip, file: a.conf"), nil, "lower-case letters"},
		"name of a check":     {one("name: http_flood, enabled: true, type: ip, file: a.conf"), nil, "is the name of a check"},
		"name of Lists":       {one("name: lists, enabled: true, type: ip, file: a.conf"), nil, "is the name of a check"},
		"duplicate name":      {"Lists:\n  - {" + valid + "}\n  - {" + valid + "}\n", map[string]string{"a.conf": ""}, "duplicate name"},
		"no enabled":          {one("name: a, type: ip, file: a.conf"), nil, "enabled"},
		"no type":             {one("name: a, enabled: true, file: a.conf"), nil, "type"},
		"unknown type":        {one("name: a, enabled: true, type: asn, file: a.conf"), nil, "type"},
		"no file":             {one("name: a, enabled: true, type: ip"), nil, "file"},
		"missing file":        {one(valid), nil, "a.conf"},
		"unknown action":      {one(valid + ", action: challenge_unverified"), map[string]string{"a.conf": ""}, "action"},
		"unknown key":         {one(valid + ", comment: x"), map[string]string{"a.conf": ""}, "comment"},
		"bad address":         {one(valid), map[string]string{"a.conf": "192.0.2.1\nnot-an-ip\n"}, "a.conf:2: invalid IP or CIDR"},
		"bad network":         {one(valid), map[string]string{"a.conf": "192.0.2.0/33\n"}, "a.conf:1"},
		"bad regex":           {one("name: a, enabled: true, type: url, file: a.conf"), map[string]string{"a.conf": "regex:(\n"}, "invalid regular expression"},
		"old-style regex":     {one("name: a, enabled: true, type: url, file: a.conf"), map[string]string{"a.conf": "/ok\n^/api/.*$\n"}, "a.conf:2"},
		"old IPAllow section": {"IPAllow: {enabled: true}\n", nil, `unknown field "IPAllow"`},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := LoadRules(listsDirectory(t, tt.settings, tt.files))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want one containing %q", err, tt.want)
			}
		})
	}
}

// Custom rules refer to a list as $name; a rule that names a list that does not exist, or one of
// the wrong type, rejects the file.
func TestCustomRulesReferToLists(t *testing.T) {
	rule := func(expression string) string {
		return listsFixture + "CustomRules:\n  enabled: true\n  rules:\n    - {id: r, action: block, expression: '" + expression + "'}\n"
	}
	for name, tt := range map[string]struct {
		expression string
		want       string // "" means the file loads
	}{
		"ip list":                 {"ip.src in $partners", ""},
		"negated":                 {"not ip.src in $office and http.request.uri.path in $login", ""},
		"a disabled list":         {"ip.src in $bad_networks", ""},
		"unknown list":            {"ip.src in $nope", `no list named "nope"`},
		"url list for an address": {"ip.src in $login", "holds url entries"},
		"ip list for a string":    {"http.host in $office", "holds ip entries"},
		"list for a number":       {"len(http.host) in $office", "cannot be compared"},
		"no name":                 {"ip.src in $", "expected a list name"},
	} {
		t.Run(name, func(t *testing.T) {
			rules, err := LoadRules(listsDirectory(t, rule(tt.expression), listFiles))
			if tt.want == "" {
				if err != nil || len(rules.CustomRules.Rules) != 1 {
					t.Fatalf("LoadRules: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want one containing %q", err, tt.want)
			}
		})
	}
}
