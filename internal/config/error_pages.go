package config

import (
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"path/filepath"
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
	pages := &ErrorPages{}
	for p, name := range pageFiles {
		tpl, err := template.ParseFiles(filepath.Join(dir, name))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				log.Printf("[WARN] Error page %s not found in %s; requests for it will return 500", name, dir)
				continue
			}
			return nil, fmt.Errorf("failed to parse error page %s: %w", name, err)
		}
		pages.tpl[p] = tpl
	}
	return pages, nil
}
