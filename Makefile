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

all: wireguard-go

export GOPATH := $(CURDIR)/.gopath
export PATH := $(PATH):$(CURDIR)/.gopath/bin
GO_IMPORT_PATH := git.zx2c4.com/wireguard-go

version.go:
	@export GIT_CEILING_DIRECTORIES="$(realpath $(CURDIR)/..)" && \
	tag="$$(git describe --dirty 2>/dev/null)" && \
	ver="$$(printf 'package main\nconst WireGuardGoVersion = "%s"\n' "$$tag")" && \
	[ "$$(cat $@ 2>/dev/null)" != "$$ver" ] && \
	echo "$$ver" > $@ && \
	git update-index --assume-unchanged $@ || true

.gopath/.created:
	rm -rf .gopath
	mkdir -p $(dir .gopath/src/$(GO_IMPORT_PATH))
	ln -s ../../.. .gopath/src/$(GO_IMPORT_PATH)
	touch $@

vendor/.created: Gopkg.toml Gopkg.lock | .gopath/.created
	command -v dep >/dev/null || go get -v github.com/golang/dep/cmd/dep
	export PWD; cd .gopath/src/$(GO_IMPORT_PATH) && dep ensure -vendor-only -v
	touch $@

wireguard-go: $(wildcard *.go) $(wildcard */*.go) .gopath/.created vendor/.created version.go
	go build -v $(GO_IMPORT_PATH)

install: wireguard-go
	@install -v -d "$(DESTDIR)$(BINDIR)" && install -v -m 0755 wireguard-go "$(DESTDIR)$(BINDIR)/wireguard-go"

clean:
	rm -f wireguard-go

update-dep: | .gopath/.created
	command -v dep >/dev/null || go get -v github.com/golang/dep/cmd/dep
	cd .gopath/src/$(GO_IMPORT_PATH) && dep ensure -update -v

.PHONY: clean install update-dep version.go
