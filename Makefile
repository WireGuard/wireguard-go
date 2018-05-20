PREFIX ?= /usr
DESTDIR ?=
BINDIR ?= $(PREFIX)/bin

ifeq ($(shell go env GOOS),linux)
ifeq ($(wildcard .git),)
$(error Do not build this for Linux. Instead use the Linux kernel module. See wireguard.com/install/ for more info.)
endif
endif

all: wireguard-go

wireguard-go: $(wildcard *.go) $(wildcard */*.go)
	go build -v -o $@

install: wireguard-go
	@install -v -d "$(DESTDIR)$(BINDIR)" && install -m 0755 -v wireguard-go "$(DESTDIR)$(BINDIR)/wireguard-go"

clean:
	rm -f wireguard-go

.PHONY: clean install
