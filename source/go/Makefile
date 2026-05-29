VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -s -w -X github.com/bluedoors/ccwb-binaries/internal/version.Version=$(VERSION)
# Windows: do NOT strip (-s -w). Defender cloud ML (Wacatac.B!ml) flags
# stripped Go binaries and blocks them in subprocess/non-interactive contexts.
# The .syso PE version-info files help but are not sufficient alone.
LDFLAGS_WIN := -X github.com/bluedoors/ccwb-binaries/internal/version.Version=$(VERSION)
OUT ?= bin

# macOS Developer ID signing + notarization
CODESIGN_IDENTITY ?= Developer ID Application: Luis Florez (6Z8H988K7H)
NOTARYTOOL_PROFILE ?= notarytool-profile

.PHONY: all test clean fmt vet macos-arm64 macos-intel linux-x64 linux-arm64 windows notarize

all: macos-arm64 macos-intel linux-x64 linux-arm64 windows

test:
	go test ./... -v

fmt:
	go fmt ./...

vet:
	go vet ./...

clean:
	rm -rf $(OUT)

macos-arm64:
	@mkdir -p $(OUT)
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(OUT)/credential-process-macos-arm64 ./cmd/credential-process/
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(OUT)/otel-helper-macos-arm64 ./cmd/otel-helper/
	codesign --force --options runtime --sign "$(CODESIGN_IDENTITY)" $(OUT)/credential-process-macos-arm64
	codesign --force --options runtime --sign "$(CODESIGN_IDENTITY)" $(OUT)/otel-helper-macos-arm64

macos-intel:
	@mkdir -p $(OUT)
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(OUT)/credential-process-macos-intel ./cmd/credential-process/
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(OUT)/otel-helper-macos-intel ./cmd/otel-helper/
	codesign --force --options runtime --sign "$(CODESIGN_IDENTITY)" $(OUT)/credential-process-macos-intel
	codesign --force --options runtime --sign "$(CODESIGN_IDENTITY)" $(OUT)/otel-helper-macos-intel

notarize: macos-arm64 macos-intel
	@echo "Packaging macOS binaries for notarization..."
	@mkdir -p $(OUT)/notarize-tmp
	zip -j $(OUT)/notarize-tmp/macos-binaries.zip \
		$(OUT)/credential-process-macos-arm64 \
		$(OUT)/otel-helper-macos-arm64 \
		$(OUT)/credential-process-macos-intel \
		$(OUT)/otel-helper-macos-intel
	@echo "Submitting to Apple for notarization..."
	xcrun notarytool submit $(OUT)/notarize-tmp/macos-binaries.zip \
		--keychain-profile "$(NOTARYTOOL_PROFILE)" --wait
	@rm -rf $(OUT)/notarize-tmp
	@echo "Notarization complete."

linux-x64:
	@mkdir -p $(OUT)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(OUT)/credential-process-linux-x64 ./cmd/credential-process/
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(OUT)/otel-helper-linux-x64 ./cmd/otel-helper/

linux-arm64:
	@mkdir -p $(OUT)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(OUT)/credential-process-linux-arm64 ./cmd/credential-process/
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(OUT)/otel-helper-linux-arm64 ./cmd/otel-helper/

windows:
	@mkdir -p $(OUT)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS_WIN)" -o $(OUT)/credential-process-windows.exe ./cmd/credential-process/
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS_WIN)" -o $(OUT)/otel-helper-windows.exe ./cmd/otel-helper/
