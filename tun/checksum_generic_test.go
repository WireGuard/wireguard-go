package tun

var archChecksumFuncs = []archChecksumDetails{
	{
		name:      "generic",
		available: true,
		f:         checksum,
	},
}
