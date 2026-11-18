package config

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestLoadErrorPages(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "403.html"), "403|{{.EdgeTag}}")
	writeFile(t, filepath.Join(dir, "error.html"), "error|{{.EdgeTag}}")

	pages, err := LoadErrorPages(dir)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := pages.Get(PageForbidden).Execute(&buf, struct{ EdgeTag string }{"n"}); err != nil || buf.String() != "403|n" {
		t.Fatalf("403 = %q, %v", buf.String(), err)
	}
	if pages.Get(PageError) == nil {
		t.Fatal("error.html not loaded")
	}
	for _, p := range []Page{PageTooManyRequests, PageCaptcha, PageCaptchaAltcha} {
		if pages.Get(p) != nil {
			t.Errorf("%s loaded although the file is missing", p)
		}
	}
	if (*ErrorPages)(nil).Get(PageForbidden) != nil || pages.Get(Page(-1)) != nil || pages.Get(pageCount) != nil {
		t.Fatal("out-of-range or nil lookup returned a template")
	}

	writeFile(t, filepath.Join(dir, "429.html"), "{{.Broken")
	if _, err := LoadErrorPages(dir); err == nil {
		t.Fatal("broken template accepted")
	}
}

func TestReloadErrorPages(t *testing.T) {
	rules := siteDirectory(t, "")
	pagesDir := t.TempDir()
	page := filepath.Join(pagesDir, "403.html")
	writeFile(t, page, "v1")
	cfg := &MainConfig{ErrorPage: pagesDir, Sites: []Site{{ID: "default_site", RulePath: rules}}}
	manager := &Manager{}
	if err := manager.Reload(cfg); err != nil {
		t.Fatal(err)
	}
	render := func() string {
		var buf bytes.Buffer
		if err := manager.Get().Pages.Get(PageForbidden).Execute(&buf, nil); err != nil {
			t.Fatal(err)
		}
		return buf.String()
	}
	if got := render(); got != "v1" {
		t.Fatalf("page = %q, want v1", got)
	}

	// Editing the file alone changes nothing until the next reload.
	writeFile(t, page, "v2")
	if got := render(); got != "v1" {
		t.Fatalf("page = %q before reload, want v1", got)
	}
	if err := manager.Reload(cfg); err != nil {
		t.Fatal(err)
	}
	if got := render(); got != "v2" {
		t.Fatalf("page = %q after reload, want v2", got)
	}

	current := manager.Get()
	writeFile(t, page, "{{.Broken")
	if err := manager.Reload(cfg); err == nil {
		t.Fatal("broken template accepted on reload")
	}
	if manager.Get() != current {
		t.Fatal("failed reload replaced snapshot")
	}

	if err := os.Remove(page); err != nil {
		t.Fatal(err)
	}
	if err := manager.Reload(cfg); err != nil {
		t.Fatalf("missing page rejected: %v", err)
	}
	if manager.Get().Pages.Get(PageForbidden) != nil {
		t.Fatal("removed page still served")
	}
}

// A site with pages of its own shows them, and the common page for every page it does not hold.
func TestSiteErrorPages(t *testing.T) {
	common, own := t.TempDir(), t.TempDir()
	writeFile(t, filepath.Join(common, "403.html"), "common 403")
	writeFile(t, filepath.Join(common, "429.html"), "common 429")
	writeFile(t, filepath.Join(own, "403.html"), "shop 403")

	render := func(pages *ErrorPages, p Page) string {
		tpl := pages.Get(p)
		if tpl == nil {
			return ""
		}
		var buf bytes.Buffer
		if err := tpl.Execute(&buf, nil); err != nil {
			t.Fatal(err)
		}
		return buf.String()
	}

	dir := writeMainConfig(t, "error_page: \""+filepath.ToSlash(common)+"\"")
	cfg, err := LoadMainConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(cfg.Sites[0].RulePath, "Server.yml"), "")
	cfg.Sites = append(cfg.Sites, Site{ID: "shop", RulePath: cfg.Sites[0].RulePath, ErrorPage: own})
	snap, err := LoadSnapshot(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for name, tt := range map[string]struct {
		site string
		page Page
		want string
	}{
		"site without pages":        {"default_site", PageForbidden, "common 403"},
		"own page":                  {"shop", PageForbidden, "shop 403"},
		"page the site lacks":       {"shop", PageTooManyRequests, "common 429"},
		"page nobody has":           {"shop", PageCaptcha, ""},
		"a site that is not listed": {"nowhere", PageForbidden, "common 403"},
	} {
		if got := render(snap.PagesFor(tt.site), tt.page); got != tt.want {
			t.Errorf("%s: page = %q, want %q", name, got, tt.want)
		}
	}

	writeFile(t, filepath.Join(own, "429.html"), "{{.Broken")
	if _, err := LoadSnapshot(cfg); err == nil {
		t.Fatal("broken page of a site accepted")
	}
}

// The pages that were not found are named, so the node can warn about them once per load
// instead of failing every request for them in silence.
func TestMissingErrorPagesAreNamed(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "403.html"), "403")
	pages, err := LoadErrorPages(dir)
	if err != nil {
		t.Fatalf("LoadErrorPages: %v", err)
	}
	missing := pages.Missing()
	if len(missing) != len(pageFiles)-1 || slices.Contains(missing, "403.html") || !slices.Contains(missing, "429.html") || !slices.IsSorted(missing) {
		t.Fatalf("missing = %v", missing)
	}
	// A site takes what it does not have from the common pages: nothing is missing of its own.
	site, err := LoadSiteErrorPages(t.TempDir(), pages)
	if err != nil {
		t.Fatalf("LoadSiteErrorPages: %v", err)
	}
	if len(site.Missing()) != 0 {
		t.Fatalf("site missing = %v", site.Missing())
	}
	if (*ErrorPages)(nil).Missing() != nil {
		t.Fatal("nil pages miss something")
	}
}
