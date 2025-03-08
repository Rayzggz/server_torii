.PHONY: all build clean install uninstall


all: build


build:
	go mod download
	go build -o server_torii .

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

