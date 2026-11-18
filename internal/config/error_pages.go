package config

import (
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"path/filepath"
	"slices"
)

// Page identifies one error page template.
type Page int

const (
	PageForbidden       Page = iota // 403.html
	PageTooManyRequests             // 429.html
	PageCaptcha                     // CAPTCHA.html
	PageCaptchaAltcha               // CAPTCHA_ALTCHA.html
	PageError                       // error.html
	pageCount
)

var pageFiles = [pageCount]string{
	PageForbidden:       "403.html",
	PageTooManyRequests: "429.html",
	PageCaptcha:         "CAPTCHA.html",
	PageCaptchaAltcha:   "CAPTCHA_ALTCHA.html",
	PageError:           "error.html",
}

// String returns the page's file name.
func (p Page) String() string {
	if p < 0 || p >= pageCount {
		return fmt.Sprintf("Page(%d)", int(p))
	}
	return pageFiles[p]
}

// ErrorPages holds the error page templates, parsed once per configuration load and shared by
// every request; html/template is safe for concurrent Execute.
type ErrorPages struct {
	tpl [pageCount]*template.Template
	// missing names the files that were not found, here or in the fallback.
	missing []string
}

// Missing returns the files of pages that were not found. A request for one is answered 500.
func (e *ErrorPages) Missing() []string {
	if e == nil {
		return nil
	}
	return e.missing
}

// Get returns the parsed template, or nil when the file was absent or pages is nil.
// The caller answers 500 in that case, as it did when parsing failed per request.
func (e *ErrorPages) Get(p Page) *template.Template {
	if e == nil || p < 0 || p >= pageCount {
		return nil
	}
	return e.tpl[p]
}

// LoadErrorPages parses every error page in dir. A missing file is tolerated so a deployment that
// does not use a page need not ship it, but a file that exists and fails to parse is an error, so a
// broken template is caught at startup or rejected on reload instead of failing each request.
func LoadErrorPages(dir string) (*ErrorPages, error) {
	return loadErrorPages(dir, nil)
}

// LoadSiteErrorPages parses the pages a site keeps in its own directory. A page the directory
// does not hold is the one of fallback.
func LoadSiteErrorPages(dir string, fallback *ErrorPages) (*ErrorPages, error) {
	return loadErrorPages(dir, fallback)
}

func loadErrorPages(dir string, fallback *ErrorPages) (*ErrorPages, error) {
	pages := &ErrorPages{}
	for p, name := range pageFiles {
		tpl, err := template.ParseFiles(filepath.Join(dir, name))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				if fallback != nil {
					pages.tpl[p] = fallback.tpl[p]
					continue
				}
				pages.missing = append(pages.missing, name)
				continue
			}
			return nil, fmt.Errorf("failed to parse error page %s: %w", name, err)
		}
		pages.tpl[p] = tpl
	}
	slices.Sort(pages.missing)
	return pages, nil
}
