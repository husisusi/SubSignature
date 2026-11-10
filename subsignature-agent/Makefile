VERSION ?= 0.4.0-alpha
LDFLAGS := -s -w -X subsignature-agent/internal/version.Version=$(VERSION)
GOBUILD := CGO_ENABLED=0 go build -trimpath

.PHONY: all build test vet dist dist-linux dist-windows clean

all: vet test build

# For the system the build runs on
build:
	$(GOBUILD) -ldflags '$(LDFLAGS)' -o bin/ ./cmd/subsignature-agent ./cmd/mocksubsig

test:
	go test -race -count=1 ./...

# The code must be clean for both systems, even when building on only one.
vet:
	gofmt -l . | (! grep .)
	GOOS=linux go vet ./...
	GOOS=windows go vet ./...

dist: dist-linux dist-windows

# Static binaries for Linux (amd64 and arm64)
dist-linux:
	mkdir -p dist
	GOOS=linux GOARCH=amd64 $(GOBUILD) -ldflags '$(LDFLAGS)' -o dist/subsignature-agent-linux-amd64 ./cmd/subsignature-agent
	GOOS=linux GOARCH=arm64 $(GOBUILD) -ldflags '$(LDFLAGS)' -o dist/subsignature-agent-linux-arm64 ./cmd/subsignature-agent

# Windows: one folder per architecture with everything install.ps1 needs.
#   subsignature-agent.exe   console program (ping, check, sync, status, remove ...)
#   subsignature-agentw.exe  the same without a console window, for autostart ("run")
dist-windows:
	for arch in amd64 arm64; do \
	  d=dist/windows-$$arch; mkdir -p $$d; \
	  GOOS=windows GOARCH=$$arch $(GOBUILD) -ldflags '$(LDFLAGS)' -o $$d/subsignature-agent.exe ./cmd/subsignature-agent || exit 1; \
	  GOOS=windows GOARCH=$$arch $(GOBUILD) -ldflags '$(LDFLAGS) -H=windowsgui' -o $$d/subsignature-agentw.exe ./cmd/subsignature-agent || exit 1; \
	  GOOS=windows GOARCH=$$arch $(GOBUILD) -ldflags '$(LDFLAGS)' -o $$d/mocksubsig.exe ./cmd/mocksubsig || exit 1; \
	  cp packaging/windows/install.ps1 packaging/windows/uninstall.ps1 internal/config/config.example.xml $$d/; \
	done

clean:
	rm -rf bin dist
