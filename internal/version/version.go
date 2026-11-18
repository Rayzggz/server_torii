package version

import (
	"runtime/debug"
	"sync"
)

const Version string = "2.0.0-beta"

// buildCommit is injected at build time, e.g.
//
//	go build -ldflags "-X server_torii/internal/version.buildCommit=$(git rev-parse --short HEAD)"
//
// It must stay a plain string var (not a const) for -X to work.
var buildCommit string

// Commit returns the git commit the binary was built from: the
// -ldflags value if set, otherwise the VCS info the Go toolchain embeds when
// building inside a git checkout, otherwise "unknown".
var Commit = sync.OnceValue(func() string {
	if buildCommit != "" {
		return buildCommit
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	var revision string
	var modified bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}
	if revision == "" {
		return "unknown"
	}
	if len(revision) > 7 {
		revision = revision[:7]
	}
	if modified {
		revision += "-dirty"
	}
	return revision
})
