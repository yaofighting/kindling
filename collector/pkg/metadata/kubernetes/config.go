package kubernetes

import (
	"time"

	"k8s.io/client-go/tools/cache"
)

// config contains optional settings for connecting to kubernetes.
type config struct {
	KubeAuthType  AuthType
	KubeConfigDir string
	// GraceDeletePeriod controls the delay interval after receiving delete event.
	// The unit is seconds, and the default value is 60 seconds.
	// Should not be lower than 30 seconds.
	GraceDeletePeriod time.Duration

	// DSFRule
	DSFConfig *DSFConfig `mapstructure:"dsf_config"`

	MetaDataProviderConfig *MetaDataProviderConfig `mapstructure:"metadata_provider_config"`

	listAndWatchFromProvider func() error

	podEventHander     cache.ResourceEventHandler
	rsEventHander      cache.ResourceEventHandler
	nodeEventHander    cache.ResourceEventHandler
	serviceEventHander cache.ResourceEventHandler
}

type MetaDataProviderConfig struct {
	Enable   bool   `mapstructure:"enable"`
	Debug    bool   `mapstructure:"debug"`
	Endpoint string `mapstructure:"endpoint"`
}

type DSFConfig struct {
	Enable           bool          `mapstructure:"enable"`
	ConfigServerAddr string        `mapstructure:"config_server_addr"`
	InitEndpoint     string        `mapstructure:"init_endpoint"`
	UpdateEndpoint   string        `mapstructure:"update_endpoint"`
	SyncInterval     time.Duration `mapstructure:"sync_interval"`
	EnableDebug      bool          `mapstructure:"debug"`
}

type Option func(cfg *config)

// WithAuthType sets way of authenticating kubernetes api-server
// Supported AuthTypeNone, AuthTypeServiceAccount, AuthTypeKubeConfig
func WithAuthType(authType AuthType) Option {
	return func(cfg *config) {
		cfg.KubeAuthType = authType
	}
}

// WithKubeConfigDir sets the directory where the file "kubeconfig" is stored
func WithKubeConfigDir(dir string) Option {
	return func(cfg *config) {
		cfg.KubeConfigDir = dir
	}
}

// WithGraceDeletePeriod sets the graceful period of deleting Pod's metadata
// after receiving "delete" event from client-go.
func WithGraceDeletePeriod(interval int) Option {
	return func(cfg *config) {
		cfg.GraceDeletePeriod = time.Duration(interval) * time.Second
	}
}

func WithDSFConfig(dsfCfg *DSFConfig) Option {
	return func(cfg *config) {
		cfg.DSFConfig.Enable = dsfCfg.Enable
		cfg.DSFConfig.ConfigServerAddr = dsfCfg.ConfigServerAddr
		cfg.DSFConfig.SyncInterval = dsfCfg.SyncInterval
		if dsfCfg.InitEndpoint != "" {
			cfg.DSFConfig.InitEndpoint = dsfCfg.InitEndpoint
		}
		if dsfCfg.UpdateEndpoint != "" {
			cfg.DSFConfig.UpdateEndpoint = dsfCfg.UpdateEndpoint
		}
	}
}

func WithMetaDataProviderConfig(mpCfg *MetaDataProviderConfig, listAndWatch func() error) Option {
	return func(cfg *config) {
		cfg.MetaDataProviderConfig = mpCfg
		cfg.listAndWatchFromProvider = listAndWatch
	}
}

func WithPodEventHander(handler cache.ResourceEventHandler) Option {
	return func(cfg *config) {
		cfg.podEventHander = handler
	}
}

func WithServiceEventHander(handler cache.ResourceEventHandler) Option {
	return func(cfg *config) {
		cfg.serviceEventHander = handler
	}
}

func WithNodeEventHander(handler cache.ResourceEventHandler) Option {
	return func(cfg *config) {
		cfg.nodeEventHander = handler
	}
}

func WithReplicaSetEventHander(handler cache.ResourceEventHandler) Option {
	return func(cfg *config) {
		cfg.rsEventHander = handler
	}
}
