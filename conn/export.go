package conn

const (
	UdpSegmentMaxDatagrams = udpSegmentMaxDatagrams
)

var (
	SplitCoalescedMessages = splitCoalescedMessages
	GetSrcFromControl      = getSrcFromControl

	GetGSOSize = getGSOSize

	// export controlFns for Android to use
	// is not thread safe and should only be modified during init.
	ControlFns = &controlFns
)
