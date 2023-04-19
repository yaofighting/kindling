package detect

import "github.com/Kindling-project/kindling/collector/pkg/extension/detect/export/config"

type Config struct {
	// Enable 决定了是否启用可用性探测模块
	Enable           bool          `mapstructure:"enable"`
	HTTPClientConfig config.Config `mapstructure:",squash"`
	BatchConfig      BatchConfig   `mapstructure:",squash"`
}
