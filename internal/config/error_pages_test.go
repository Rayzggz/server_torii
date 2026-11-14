package config

import (
	"bytes"
	"os"
	"path/filepath"
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
	rules := ipCaptchaDirectory(t, "")
	pagesDir := t.TempDir()
	page := filepath.Join(pagesDir, "403.html")
	writeFile(t, page, "v1")
	cfg := &MainConfig{ErrorPage: pagesDir, Sites: []AllSiteRuleSet{{ID: "default_site", RulePath: rules}}}
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
