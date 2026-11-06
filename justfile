BINARY_NAME := "1pux2kdbx"
BINARY_PATH := "./" + BINARY_NAME
CMD_PATH := "./cmd/" + BINARY_NAME
VERSION := `git describe --tags --always --dirty 2>/dev/null || echo "dev"`
BUILD_FLAGS := "-ldflags \"-X main.version=" + VERSION + "\""

export KEEPASSXC_CLI := env("KEEPASSXC_CLI", "/Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli")

build:
    @go build {{BUILD_FLAGS}} -o {{BINARY_PATH}} {{CMD_PATH}}

install:
    @go install {{BUILD_FLAGS}} {{CMD_PATH}}

test:
    @go test -race ./...

test-verbose:
    @go test -race -v ./...

test-coverage:
    @go test -coverprofile=coverage.out ./...
    @go tool cover -html=coverage.out -o coverage.html
    @echo "Coverage report generated: coverage.html"

fmt:
    @gofmt -w .

lint:
    @golangci-lint run ./...

# Same checks as CI and the pre-commit hook
check:
    test -z "$(gofmt -l .)"
    just lint
    just test

# Point git at the repo hooks
setup:
    git config core.hooksPath .githooks

clean:
    @rm -f {{BINARY_PATH}} coverage.out coverage.html
    @go clean

# Show current version and what the next version would be based on conventional commits
# Requires: go install github.com/caarlos0/svu/v3@latest
version:
    @echo "Current: $(svu current)"
    @echo "Next:    $(svu next --v0)"

# Convert a fresh 1Password export and merge it into the long-lived backup kdbx.
# The first run (no backup yet) just writes the converted file as the backup.
# Later runs show a dry-run merge, ask for confirmation, then merge.
#
#   just sync ~/Downloads/1PasswordExport-*.1pux ~/Passwords/backup.kdbx
sync export backup: build
    #!/usr/bin/env bash
    set -euo pipefail
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT

    if [[ -z "${KDBX_PASSWORD:-}" ]]; then
      read -rsp "kdbx password: " KDBX_PASSWORD; echo
      export KDBX_PASSWORD
    fi

    fresh="$tmp/fresh.kdbx"
    if [[ ! -f "{{backup}}" ]]; then
      {{BINARY_PATH}} -in "{{export}}" -out "$fresh"
      mv "$fresh" "{{backup}}"
      echo "created {{backup}}"
      exit 0
    fi
    # -previous tags entries whose items are gone from this export.
    {{BINARY_PATH}} -in "{{export}}" -out "$fresh" -previous "{{backup}}"

    cp "{{backup}}" "{{backup}}.bak"
    # No -q here: it also hides the list of changes we want to review.
    echo "$KDBX_PASSWORD" | "$KEEPASSXC_CLI" merge -s --dry-run "{{backup}}" "$fresh" 2>&1 | grep -v "^Enter password"
    read -rp "apply merge? [y/N] " ok
    [[ $ok == y ]] || exit 1
    echo "$KDBX_PASSWORD" | "$KEEPASSXC_CLI" merge -q -s "{{backup}}" "$fresh"
    echo "merged into {{backup}} (previous copy at {{backup}}.bak)"
