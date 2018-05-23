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

.gopath/.created:
	rm -rf .gopath
	mkdir -p $(dir .gopath/src/$(GO_IMPORT_PATH))
	ln -s ../../.. .gopath/src/$(GO_IMPORT_PATH)
	touch $@

vendor/.created: Gopkg.toml Gopkg.lock .gopath/.created
	command -v dep >/dev/null || go get -v github.com/golang/dep/cmd/dep
	cd .gopath/src/$(GO_IMPORT_PATH) && dep ensure -vendor-only -v
	touch $@

wireguard-go: $(wildcard *.go) $(wildcard */*.go) .gopath/.created vendor/.created
	go build $(GO_BUILD_EXTRA_ARGS) -v $(GO_IMPORT_PATH)

install: wireguard-go
	@install -v -d "$(DESTDIR)$(BINDIR)" && install -v -m 0755 wireguard-go "$(DESTDIR)$(BINDIR)/wireguard-go"

clean:
	rm -f wireguard-go

update-dep:
	command -v dep >/dev/null || go get -v github.com/golang/dep/cmd/dep
	cd .gopath/src/$(GO_IMPORT_PATH) && dep ensure -update -v

.PHONY: clean install update-dep
