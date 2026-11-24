package conn

// Service pass inner packet info to outer bind
type Service interface {
	ID() uint64
}

// ServiceFn process inner packet and return service info and drop flag
type ServiceFn func(buff []byte) (service Service, shouldDrop bool)

var serviceFns []ServiceFn

// RegisterServiceFn register service function to identify packet
func RegisterServiceFn(fn ServiceFn) {
	serviceFns = append(serviceFns, fn)
}

// ExecuteServiceFns to process packet data
func ExecuteServiceFns(buff []byte) (service Service, shouldDrop bool) {
	finalService := Service(nil)
	for _, fn := range serviceFns {
		service, shouldDrop = fn(buff)
		if service != nil {
			finalService = service
		}
		if shouldDrop {
			return finalService, true
		}
	}
	return finalService, false
}
