PREFIX ?= /usr
DESTDIR ?=
BINDIR ?= $(PREFIX)/bin

all: wireguard-go

wireguard-go: $(wildcard *.go) $(wildcard */*.go)
	go get -d -v
	go build -v -o $@

install: wireguard-go
	@install -v -d "$(DESTDIR)$(BINDIR)" && install -m 0755 -v wireguard-go "$(DESTDIR)$(BINDIR)/wireguard-go"

clean:
	rm -f wireguard-go

.PHONY: clean install
