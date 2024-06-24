package flags

type Options struct {
	InterfaceName string

	MTU         int
	Foreground  bool
	ShowVersion bool
}

func NewOptions() *Options {
	return &Options{}
}
