PREFIX ?= /usr
DESTDIR ?=
BINDIR ?= $(PREFIX)/bin
export GOPATH ?= $(CURDIR)/.gopath
export GO111MODULE := on

all: generate-version-and-build

ifeq ($(shell go env GOOS)|$(wildcard .git),linux|)
$(error Do not build this for Linux. Instead use the Linux kernel module. See wireguard.com/install/ for more info.)
else
ireallywantobuildon_linux.go:
	@printf "WARNING: This software is meant for use on non-Linux\nsystems. For Linux, please use the kernel module\ninstead. See wireguard.com/install/ for more info.\n\n" >&2
	@printf 'package main\nconst UseTheKernelModuleInstead = 0xdeadbabe\n' > "$@"
clean-ireallywantobuildon_linux.go:
	@rm -f ireallywantobuildon_linux.go
.PHONY: clean-ireallywantobuildon_linux.go
clean: clean-ireallywantobuildon_linux.go
wireguard-go: ireallywantobuildon_linux.go
endif

MAKEFLAGS += --no-print-directory

generate-version-and-build:
	@export GIT_CEILING_DIRECTORIES="$(realpath $(CURDIR)/..)" && \
	tag="$$(git describe --dirty 2>/dev/null)" && \
	ver="$$(printf 'package main\nconst WireGuardGoVersion = "%s"\n' "$$tag")" && \
	[ "$$(cat version.go 2>/dev/null)" != "$$ver" ] && \
	echo "$$ver" > version.go && \
	git update-index --assume-unchanged version.go || true
	@$(MAKE) wireguard-go

wireguard-go: $(wildcard *.go) $(wildcard */*.go)
	go build -v -o "$@"

install: wireguard-go
	@install -v -d "$(DESTDIR)$(BINDIR)" && install -v -m 0755 "$<" "$(DESTDIR)$(BINDIR)/wireguard-go"

clean:
	rm -f wireguard-go

.PHONY: all clean install generate-version-and-build
