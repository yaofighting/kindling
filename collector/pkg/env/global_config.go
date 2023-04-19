package env

// 一部分的配置作为通用配置，被存储到  组件本身 config ，global_config 和 environment 中 ， 避免重复配置
// 优先级依次为 config > global_config > environment > defaultValue , DefaultValue 通常为None开头，用于表示该配置项未正常配置

type GlobalConfig struct {
	MasterIp         *string `json:"masterIp"`
	ReceiverAddr     *string `json:"receiver_addr"`
	ConfigServerAddr *string `json:"configserver_addr"`
}
