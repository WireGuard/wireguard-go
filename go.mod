module golang.zx2c4.com/wireguard

go 1.12

require (
	github.com/Microsoft/go-winio v0.0.0-20190429060359-b01600290cd4
	golang.org/x/crypto v0.0.0-20190411191339-88737f569e3a
	golang.org/x/net v0.0.0-20190404232315-eb5bcb51f2a3
	golang.org/x/sys v0.0.0-20190412213103-97732733099d
)

replace github.com/Microsoft/go-winio => golang.zx2c4.com/wireguard/windows v0.0.0-20190429060359-b01600290cd4
