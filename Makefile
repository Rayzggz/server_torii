.PHONY: all build tidy clean install uninstall reinstall test-e2e upgrade

all: build

# Dependencies are pinned by the committed go.mod/go.sum. Run `make tidy`
# after adding or removing imports, then commit both files.
tidy:
	go mod tidy

# Short commit hash (plus "-dirty" for uncommitted changes), shown by the
# health check. Empty outside a git checkout; the binary then falls back to
# the VCS info Go embeds, or "unknown". Override with `make COMMIT=...`.
COMMIT ?= $(shell h=$$(git rev-parse --short=7 HEAD 2>/dev/null) && { git diff --quiet HEAD 2>/dev/null || h="$$h-dirty"; echo "$$h"; })
LDFLAGS := -X server_torii/internal/version.buildCommit=$(COMMIT)

build:
	go build -ldflags "$(LDFLAGS)" -o server_torii ./cmd/server_torii

test-e2e:
	bash tests/e2e/test.sh

clean:
	rm -f server_torii

install: build
	$(eval CURDIR=$(shell pwd))
	$(eval SERVICE_FILE = "/etc/systemd/system/server_torii.service")
	@echo "[Unit]" > $(SERVICE_FILE)
	@echo "Description=Server Torii Service" >> $(SERVICE_FILE)
	@echo "After=network.target" >> $(SERVICE_FILE)
	@echo "" >> $(SERVICE_FILE)
	@echo "[Service]" >> $(SERVICE_FILE)
	@echo "ExecStart=$(CURDIR)/server_torii" >> $(SERVICE_FILE)
	@echo "WorkingDirectory=$(CURDIR)" >> $(SERVICE_FILE)
	@echo "Restart=always" >> $(SERVICE_FILE)
	@echo "" >> $(SERVICE_FILE)
	@echo "[Install]" >> $(SERVICE_FILE)
	@echo "WantedBy=multi-user.target" >> $(SERVICE_FILE)

	systemctl daemon-reload
	systemctl enable server_torii
	systemctl start server_torii

uninstall:
	systemctl stop server_torii
	systemctl disable server_torii
	rm -f /etc/systemd/system/server_torii.service
	systemctl daemon-reload

reinstall: uninstall install

# Build while the old process serves traffic, then restart.
# Run from the same directory used for `make install`, with systemd permissions.
upgrade: build
	systemctl restart server_torii.service
	systemctl --no-pager status server_torii.service

