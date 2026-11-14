package urllist

import "testing"

func TestListMatch(t *testing.T) {
	list := &List{}
	for _, entry := range []string{"/admin", "/a.html", "/search?q=1", `regex:^/private/.*$`, `regex:\.php$`} {
		if err := list.Add(entry); err != nil {
			t.Fatalf("Add(%q): %v", entry, err)
		}
	}
	if list.Len() != 5 {
		t.Fatalf("Len = %d, want 5", list.Len())
	}
	for url, want := range map[string]bool{
		"/admin":          true,
		"/admin/":         false,
		"/admin/settings": false,
		"/a.html":         true,
		// Without the regex prefix a dot is a dot.
		"/aXhtml":         false,
		"/search?q=1":     true,
		"/private/file":   true,
		"/x/private/file": false,
		"/index.php":      true,
		"/index.php5":     false,
		"":                false,
	} {
		if got := list.Match(url); got != want {
			t.Errorf("Match(%q) = %v, want %v", url, got, want)
		}
	}
}

func TestListAddRejects(t *testing.T) {
	for _, entry := range []string{"regex:(", "^/api/.*$", "^/api", "/api/.*$"} {
		if err := (&List{}).Add(entry); err == nil {
			t.Errorf("Add(%q) accepted", entry)
		}
	}
}

func TestListNilAndEmpty(t *testing.T) {
	var none *List
	if none.Len() != 0 || none.Match("/") {
		t.Error("a nil list is not empty")
	}
	if (&List{}).Match("/") {
		t.Error("an empty list matched")
	}
}
