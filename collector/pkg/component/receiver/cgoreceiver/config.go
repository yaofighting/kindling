package cgoreceiver

type Config struct {
	SubscribeInfo []SubEvent `mapstructure:"subscribe"`
}

type SubEvent struct {
	Params   map[string]string `mapstructure:"params"`
	Category string            `mapstructure:"category"`
	Name     string            `mapstructure:"name"`
}
