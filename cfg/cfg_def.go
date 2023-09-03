package cfg

import "log"

func init() {
	if IsAdvancedSecurityOn() {
		if JunkPacketMaxSize <= JunkPacketMinSize {
			log.Fatalf(
				"MaxSize: %d; should be greater than MinSize: %d",
				JunkPacketMaxSize,
				JunkPacketMinSize,
			)
		}
		if JunkPacketCount < 0 {
			log.Fatalf("JunkPacketCount should be non negative")
		}
		const MaxSegmentSize = 2048 - 32
		if 148+InitPacketJunkSize >= MaxSegmentSize {
			log.Fatalf(
				"init packets should be smaller than maxSegmentSize: %d",
				MaxSegmentSize,
			)
		}
		if 92+ResponsePacketJunkSize >= MaxSegmentSize {
			log.Fatalf(
				"response packets should be smaller than maxSegmentSize: %d",
				MaxSegmentSize,
			)
		}
		if 64+UnderLoadPacketJunkSize >= MaxSegmentSize {
			log.Fatalf(
				"underload packets should be smaller than maxSegmentSize: %d",
				MaxSegmentSize,
			)
		}
		if 32+TransportPacketJunkSize >= MaxSegmentSize {
			log.Fatalf(
				"transport packets should be smaller than maxSegmentSize: %d",
				MaxSegmentSize,
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
	return InitPacketMagicHeader != 1
}
