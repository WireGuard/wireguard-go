package config

import (
	"io/ioutil"

	"github.com/juju/errors"
	"gopkg.in/yaml.v3"
)

type config struct {
	JunkPacketCount            int    `yaml:"junk_packet_count"`
	JunkPacketMinSize          int    `yaml:"junk_packet_min_size"`
	JunkPacketMaxSize          int    `yaml:"junk_packet_max_size"`
	InitPacketJunkSize         int    `yaml:"init_packet_junk_size"`
	ResponsePacketJunkSize     int    `yaml:"response_packet_junk_size"`
	UnderLoadPacketJunkSize    int    `yaml:"underload_packet_junk_size"`
	TransportPacketJunkSize    int    `yaml:"transport_packet_junk_size"`
	InitPacketMagicHeader      uint32 `yaml:"init_packet_magic_header"`
	ResponsePacketMagicHeader  uint32 `yaml:"response_packet_magic_header"`
	UnderloadPacketMagicHeader uint32 `yaml:"underload_packet_magic_header"`
	TransportPacketMagicHeader uint32 `yaml:"transport_packet_magic_header"`
}

// New creates a new CW from a file by the given name
func New(name string) (*config, error) {
	return NewFromFilename(name)
}

// NewFromFilename creates a new CW from a file by the given filename
func NewFromFilename(filename string) (*config, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return NewFromRaw(data)
}

// NewFromRaw creates a new CW by unmarshaling the given raw data
func NewFromRaw(raw []byte) (*config, error) {
	cfg := &config{}
	if err := yaml.Unmarshal(raw, cfg); err != nil {
		return nil, errors.Trace(err)
	}

	return cfg, nil
}

// TODO
// String can't be defined on a value receiver here because of the mutex
func (c *config) String() string {
	raw, err := yaml.Marshal(c)
	if err != nil {
		return err.Error()
	}

	return string(raw)
}
