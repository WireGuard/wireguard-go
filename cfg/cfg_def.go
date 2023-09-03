package cfg

import "log"

func init() {
	if IsAdvancedSecurityOn() {
		if JunkPacketCount < 0 {
			log.Fatalf("JunkPacketCount should be non negative")
		}
		if JunkPacketMaxSize <= JunkPacketMinSize {
			log.Fatalf(
				"MaxSize: %d; should be greater than MinSize: %d",
				JunkPacketMaxSize,
				JunkPacketMinSize,
			)
		}
		const MaxSegmentSize = 2048 - 32
		if JunkPacketMaxSize >= MaxSegmentSize {
			log.Fatalf(
				"JunkPacketMaxSize: %d; should be smaller than maxSegmentSize: %d",
				JunkPacketMaxSize,
				MaxSegmentSize,
			)
		}
		if 148+InitPacketJunkSize >= MaxSegmentSize {
			log.Fatalf(
				"init header size(148) + junkSize:%d; should be smaller than maxSegmentSize: %d",
				InitPacketJunkSize,
				MaxSegmentSize,
			)
		}
		if 92+ResponsePacketJunkSize >= MaxSegmentSize {
			log.Fatalf(
				"response header size(92) + junkSize:%d; should be smaller than maxSegmentSize: %d",
				ResponsePacketJunkSize,
				MaxSegmentSize,
			)
		}
		if 64+UnderLoadPacketJunkSize >= MaxSegmentSize {
			log.Fatalf(
				"underload packet size(64) + junkSize:%d; should be smaller than maxSegmentSize: %d",
				UnderLoadPacketJunkSize,
				MaxSegmentSize,
			)
		}
		if 32+TransportPacketJunkSize >= MaxSegmentSize {
			log.Fatalf(
				"transport packet size(32) + junkSize:%d should be smaller than maxSegmentSize: %d",
				TransportPacketJunkSize,
				MaxSegmentSize,
			)
		}
		if UnderLoadPacketJunkSize != 0 || TransportPacketJunkSize != 0 {
			log.Fatal(
				`UnderLoadPacketJunkSize and TransportPacketJunkSize; 
				are currently unimplemented and should be left 0`,
			)
		}
	} else {
		if InitPacketJunkSize != 0 ||
			ResponsePacketJunkSize != 0 ||
			UnderLoadPacketJunkSize != 0 ||
			TransportPacketJunkSize != 0 {

			log.Fatal("JunkSizes should be zero when advanced security on")
		}
	}
}

func IsAdvancedSecurityOn() bool {
	return InitPacketMagicHeader != 1 ||
		ResponsePacketMagicHeader != 2 ||
		UnderloadPacketMagicHeader != 3 ||
		TransportPacketMagicHeader != 4
}
