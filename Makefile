PREFIX ?= /usr
DESTDIR ?=
BINDIR ?= $(PREFIX)/bin
export GO111MODULE := on

all: generate-version-and-build

MAKEFLAGS += --no-print-directory

generate-version-and-build:
	@export GIT_CEILING_DIRECTORIES="$(realpath $(CURDIR)/..)" && \
	tag="$$(git describe --dirty 2>/dev/null)" && \
	ver="$$(printf 'package main\n\nconst Version = "%s"\n' "$$tag")" && \
	[ "$$(cat version.go 2>/dev/null)" != "$$ver" ] && \
	echo "$$ver" > version.go && \
	git update-index --assume-unchanged version.go || true
	@$(MAKE) wireguard-go

wireguard-go: $(wildcard *.go) $(wildcard */*.go)
	go build -v -o "$@"

install: wireguard-go
	@install -v -d "$(DESTDIR)$(BINDIR)" && install -v -m 0755 "$<" "$(DESTDIR)$(BINDIR)/wireguard-go"

test:
	go test ./...

clean:
	rm -f wireguard-go

.PHONY: all clean test install generate-version-and-build


has_args = 
# If the first argument is "cfg_gen"...
ifeq (cfg_gen,$(firstword $(MAKECMDGOALS)))
  	has_args = yes
endif

ifdef has_args
    # use the rest as arguments for "cfg_gen"
    RUN_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
    # ...and turn them into do-nothing targets
    $(eval $(RUN_ARGS):;@:)
endif

ifeq ($(OS),Windows_NT)
	gen_run=generator.exe
else 
	gen_run=./generator
endif

.PHONY: cfg_gen
cfg_gen: 
	go build util/cfgGenerator/generator.go && $(gen_run) $(RUN_ARGS)