PREFIX ?= /usr
DESTDIR ?=
BINDIR ?= $(PREFIX)/bin
export GO111MODULE := on

all: generate-version-and-build

MAKEFLAGS += --no-print-directory

generate-version-and-build:
	@export GIT_CEILING_DIRECTORIES="$(realpath $(CURDIR)/..)" && \
	tag="$$(git describe --dirty 2>/dev/null)" && \
	ver="$$(printf 'package device\nconst WireGuardGoVersion = "%s"\n' "$${tag#v}")" && \
	[ "$$(cat device/version.go 2>/dev/null)" != "$$ver" ] && \
	echo "$$ver" > device/version.go && \
	git update-index --assume-unchanged device/version.go || true
	@$(MAKE) wireguard-go

wireguard-go: $(wildcard *.go) $(wildcard */*.go)
	go build -v -o "$@"

install: wireguard-go
	@install -v -d "$(DESTDIR)$(BINDIR)" && install -v -m 0755 "$<" "$(DESTDIR)$(BINDIR)/wireguard-go"

test:
	go test -v ./...

clean:
	rm -f wireguard-go

.PHONY: all clean test install generate-version-and-build
