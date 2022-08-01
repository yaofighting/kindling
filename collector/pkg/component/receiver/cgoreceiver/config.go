package cgoreceiver

type Config struct {
	SubscribeInfo []SubEvent `mapstructure:"subscribe"`
}

type SubEvent struct {
	Params   map[string]uint64 `mapstructure:"params"`
	Category string            `mapstructure:"category"`
	Name     string            `mapstructure:"name"`
}
