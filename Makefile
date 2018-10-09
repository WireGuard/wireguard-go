PREFIX ?= /usr
DESTDIR ?=
BINDIR ?= $(PREFIX)/bin

ifeq ($(shell go env GOOS),linux)
ifeq ($(wildcard .git),)
$(error Do not build this for Linux. Instead use the Linux kernel module. See wireguard.com/install/ for more info.)
else
$(shell printf 'package main\nconst UseTheKernelModuleInstead = 0xdeadbabe\n' > ireallywantobuildon_linux.go)
endif
endif

export GOPATH ?= $(CURDIR)/.gopath

all: wireguard-go

version.go:
	@export GIT_CEILING_DIRECTORIES="$(realpath $(CURDIR)/..)" && \
	tag="$$(git describe --dirty 2>/dev/null)" && \
	ver="$$(printf 'package main\nconst WireGuardGoVersion = "%s"\n' "$$tag")" && \
	[ "$$(cat $@ 2>/dev/null)" != "$$ver" ] && \
	echo "$$ver" > $@ && \
	git update-index --assume-unchanged $@ || true

wireguard-go: $(wildcard *.go) $(wildcard */*.go)
	go build -v -o "$@"

install: wireguard-go
	@install -v -d "$(DESTDIR)$(BINDIR)" && install -v -m 0755 "$<" "$(DESTDIR)$(BINDIR)/wireguard-go"

clean:
	rm -f wireguard-go

.PHONY: clean install version.go
