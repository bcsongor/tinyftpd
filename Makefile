GO ?= go
BUILD = CGO_ENABLED=0 $(GO) build -trimpath

.PHONY: all test icon clean

all:
	GOOS=windows GOARCH=amd64 $(BUILD) -ldflags="-s -w -H=windowsgui" -o dist/tinyftpd-windows-amd64.exe ./cmd/tinyftpd
	GOOS=windows GOARCH=arm64 $(BUILD) -ldflags="-s -w -H=windowsgui" -o dist/tinyftpd-windows-arm64.exe ./cmd/tinyftpd
	GOOS=darwin GOARCH=arm64 $(BUILD) -ldflags="-s -w" -o dist/tinyftpd-darwin-arm64 ./cmd/tinyftpd
	GOOS=darwin GOARCH=amd64 $(BUILD) -ldflags="-s -w" -o dist/tinyftpd-darwin-amd64 ./cmd/tinyftpd
	GOOS=linux GOARCH=amd64 $(BUILD) -ldflags="-s -w" -o dist/tinyftpd-linux-amd64 ./cmd/tinyftpd
	GOOS=linux GOARCH=arm64 $(BUILD) -ldflags="-s -w" -o dist/tinyftpd-linux-arm64 ./cmd/tinyftpd

test:
	$(GO) test ./...

# Redraws the icon from cmd/tinyftpd/winres/icon_gen.go and rebuilds the Windows resources.
icon:
	cd cmd/tinyftpd/winres && $(GO) run icon_gen.go
	cd cmd/tinyftpd && $(GO) run github.com/tc-hib/go-winres@v0.3.3 make --arch amd64,arm64

clean:
	rm -rf dist
