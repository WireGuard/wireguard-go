all: wireguard-go

wireguard-go: $(wildcard *.go) $(wildcard */*.go)
	go build -o $@

clean:
	rm -f wireguard-go

.PHONY: clean cloc
