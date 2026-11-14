package config

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"server_torii/internal/action"
	"server_torii/internal/feature"
	"server_torii/internal/iptrie"
	"server_torii/internal/urllist"
	"strings"
)

// ListType is what a list holds.
type ListType string

const (
	ListIP  ListType = "ip"  // addresses and networks, one per line
	ListURL ListType = "url" // URLs to match exactly, or "regex:" and a regular expression
)

// List is one named list of a site: IP networks or URLs, read from a file.
//
// A list with an action is applied to every request by the Lists check, before any other check:
// the first list a request is on decides. A list without one does nothing by itself; custom
// rules refer to either kind as $name.
type List struct {
	Name string
	Type ListType
	// Enabled switches the action of the list; the connector can override it per request. Custom
	// rules that refer to the list are not affected.
	Enabled bool
	// Action is ActionAllow, ActionBlock or ActionChallenge, or ActionNone for a list that only
	// custom rules use.
	Action action.Action

	ips  *iptrie.Trie
	urls *urllist.List
}

// NewList returns an empty list, for the loader and for tests to fill.
func NewList(name string, kind ListType, act action.Action) *List {
	return &List{Name: name, Type: kind, Enabled: true, Action: act, ips: &iptrie.Trie{}, urls: &urllist.List{}}
}

// MustNewList returns a list holding entries. It panics on an entry that is not valid for the
// type of the list, so it is for lists written in code, such as the ones of tests.
func MustNewList(name string, kind ListType, act action.Action, entries ...string) *List {
	list := NewList(name, kind, act)
	add := list.AddURL
	if kind == ListIP {
		add = list.AddIP
	}
	for _, entry := range entries {
		if err := add(entry); err != nil {
			panic(fmt.Sprintf("list %s: %v", name, err))
		}
	}
	return list
}

// AddIP adds an address or a network in CIDR notation to an IP list.
func (l *List) AddIP(entry string) error {
	prefix, ok := iptrie.ParsePrefix(entry)
	if !ok {
		return fmt.Errorf("invalid IP or CIDR %q", entry)
	}
	l.ips.Insert(prefix)
	return nil
}

// AddURL adds an entry to a URL list, see urllist.List.Add.
func (l *List) AddURL(entry string) error {
	return l.urls.Add(entry)
}

// Len returns the number of entries.
func (l *List) Len() int {
	if l.Type == ListIP {
		return l.ips.Len()
	}
	return l.urls.Len()
}

// ContainsAddr reports whether an IP list holds a network addr lies in.
func (l *List) ContainsAddr(addr netip.Addr) bool {
	return l != nil && l.Type == ListIP && l.ips.Contains(addr)
}

// ContainsURL reports whether a URL list matches uri.
func (l *List) ContainsURL(uri string) bool {
	return l != nil && l.Type == ListURL && l.urls.Match(uri)
}

// Matches reports whether the request of the client at addr for uri is on the list.
func (l *List) Matches(addr netip.Addr, uri string) bool {
	if l.Type == ListIP {
		return l.ips.Contains(addr)
	}
	return l.urls.Match(uri)
}

// ListSet is the lists of a site, in the order of its Server.yml.
type ListSet struct {
	lists  []*List
	byName map[string]*List
}

// NewListSet returns a set of the given lists. Names must be unique.
func NewListSet(lists ...*List) *ListSet {
	set := &ListSet{byName: make(map[string]*List, len(lists))}
	for _, l := range lists {
		set.lists = append(set.lists, l)
		set.byName[l.Name] = l
	}
	return set
}

// All returns the lists in the order they are applied.
func (s *ListSet) All() []*List {
	if s == nil {
		return nil
	}
	return s.lists
}

// ByName returns the list called name, or nil.
func (s *ListSet) ByName(name string) *List {
	if s == nil {
		return nil
	}
	return s.byName[name]
}

// IPMatcher and StringMatcher let a custom rule refer to a list as $name: an IP field to an IP
// list, a string field to a URL list.
func (s *ListSet) IPMatcher(name string) (func(netip.Addr) bool, error) {
	l, err := s.referenced(name, ListIP)
	if err != nil {
		return nil, err
	}
	return l.ips.Contains, nil
}

func (s *ListSet) StringMatcher(name string) (func(string) bool, error) {
	l, err := s.referenced(name, ListURL)
	if err != nil {
		return nil, err
	}
	return l.urls.Match, nil
}

func (s *ListSet) referenced(name string, want ListType) (*List, error) {
	l := s.ByName(name)
	if l == nil {
		return nil, fmt.Errorf("no list named %q", name)
	}
	if l.Type != want {
		return nil, fmt.Errorf("list %q holds %s entries, the field needs a list of type %s", name, l.Type, want)
	}
	return l, nil
}

// AllowsAddr and AllowsURL report whether an enabled allow list holds the address or URL. The
// traffic analyzer leaves such clients and URLs alone.
func (s *ListSet) AllowsAddr(addr netip.Addr) bool {
	for _, l := range s.All() {
		if l.Enabled && l.Action == action.ActionAllow && l.ContainsAddr(addr) {
			return true
		}
	}
	return false
}

func (s *ListSet) AllowsURL(uri string) bool {
	for _, l := range s.All() {
		if l.Enabled && l.Action == action.ActionAllow && l.ContainsURL(uri) {
			return true
		}
	}
	return false
}

type listWrapper struct {
	Name    string   `yaml:"name" validate:"required,max=32"`
	Enabled *bool    `yaml:"enabled" validate:"required"`
	Type    ListType `yaml:"type" validate:"required,oneof=ip url"`
	File    string   `yaml:"file" validate:"required"`
	Action  string   `yaml:"action"`
}

// validListName reports whether name can be written in a Torii-Features header and after "$" in
// a rule expression: lower-case letters, digits and underscores.
func validListName(name string) bool {
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return name != ""
}

// mapLists reads the lists of a site. File paths are relative to dir, the directory of Server.yml.
func mapLists(wrappers []listWrapper, dir string) (*ListSet, error) {
	lists := make([]*List, 0, len(wrappers))
	seen := make(map[string]bool, len(wrappers))
	for i, w := range wrappers {
		label := fmt.Sprintf("Lists[%d]", i)
		if w.Name != "" {
			label = fmt.Sprintf("Lists %q", w.Name)
		}
		if err := validateStruct(&w, label); err != nil {
			return nil, err
		}
		switch {
		case !validListName(w.Name):
			return nil, fmt.Errorf("%s: name: use lower-case letters, digits and underscores", label)
		case seen[w.Name]:
			return nil, fmt.Errorf("%s: duplicate name", label)
		}
		// The connector switches checks and lists by name in the same header.
		if _, isCheck := feature.ByName(w.Name); isCheck {
			return nil, fmt.Errorf("%s: name: %q is the name of a check", label, w.Name)
		}
		seen[w.Name] = true

		act := action.ActionNone
		if w.Action != "" {
			var err error
			if act, err = action.Parse(w.Action, action.ActionAllow, action.ActionBlock, action.ActionChallenge); err != nil {
				return nil, fmt.Errorf("%s: action: %w", label, err)
			}
		}
		list := NewList(w.Name, w.Type, act)
		list.Enabled = *w.Enabled

		path := w.File
		if !filepath.IsAbs(path) {
			path = filepath.Join(dir, path)
		}
		if err := loadListFile(path, list); err != nil {
			return nil, fmt.Errorf("%s: %w", label, err)
		}
		lists = append(lists, list)
	}
	return NewListSet(lists...), nil
}

// loadListFile reads the entries of a list, one per line. Blank lines and lines starting with
// "#" are skipped. Any other line that is not a valid entry is an error: skipping it would
// leave a rule out unnoticed.
func loadListFile(path string, list *List) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }() // read-only; a Close error cannot lose data

	add := list.AddURL
	if list.Type == ListIP {
		add = list.AddIP
	}
	scanner := bufio.NewScanner(file)
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if err := add(line); err != nil {
			return fmt.Errorf("%s:%d: %w", path, lineNo, err)
		}
	}
	return scanner.Err()
}
