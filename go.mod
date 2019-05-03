module golang.zx2c4.com/wireguard

go 1.12

require (
	github.com/Microsoft/go-winio v0.4.12
	github.com/pkg/errors v0.8.1 // indirect
	golang.org/x/crypto v0.0.0-20190426145343-a29dc8fdc734
	golang.org/x/net v0.0.0-20190502183928-7f726cade0ab
	golang.org/x/sys v0.0.0-20190502175342-a43fa875dd82
)

replace github.com/Microsoft/go-winio => golang.zx2c4.com/wireguard/windows v0.0.0-20190429060359-b01600290cd4
