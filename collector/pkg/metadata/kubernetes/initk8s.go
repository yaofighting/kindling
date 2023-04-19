package kubernetes

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// AuthType describes the type of authentication to use for the K8s API
type AuthType string

const (
	// AuthTypeNone means no auth is required
	AuthTypeNone AuthType = "none"
	// AuthTypeServiceAccount means to use the built-in service account that
	// K8s automatically provisions for each pod.
	AuthTypeServiceAccount AuthType = "serviceAccount"
	// AuthTypeKubeConfig uses local credentials like those used by kubectl.
	AuthTypeKubeConfig AuthType = "kubeConfig"
	// Default kubeconfig path
	DefaultKubeConfigPath string = "~/.kube/config"
	// Default grace delete period is 60 seconds
	DefaultGraceDeletePeriod time.Duration = time.Second * 60
)

var DefaultDSFConfig *DSFConfig = &DSFConfig{
	Enable:         false,
	InitEndpoint:   "/hcmine/config/dsfInit",
	UpdateEndpoint: "/hcmine/config/dsfUpdate",
	SyncInterval:   5 * time.Second,
}

var DefaultMetaDataProviderConfig *MetaDataProviderConfig = &MetaDataProviderConfig{
	Enable:   false,
	Endpoint: "http://localhost:9504/listAndWatch",
}

var authTypes = map[AuthType]bool{
	AuthTypeNone:           true,
	AuthTypeServiceAccount: true,
	AuthTypeKubeConfig:     true,
}

// APIConfig contains options relevant to connecting to the K8s API
type APIConfig struct {
	// How to authenticate to the K8s API server.  This can be one of `none`
	// (for no auth), `serviceAccount` (to use the standard service account
	// token provided to the agent pod), or `kubeConfig` to use credentials
	// from user-defined file
	AuthType     AuthType `mapstructure:"auth_type"`
	AuthFilePath string
}

// Validate validates the K8s API config
func (c APIConfig) Validate() error {
	if !authTypes[c.AuthType] {
		return fmt.Errorf("invalid authType for kubernetes: %v", c.AuthType)
	}

	return nil
}

var (
	MetaDataCache = New()
	KubeClient    *k8s.Clientset
	once          sync.Once

	dsfEnable bool = false
)

func RLockMetadataCache() {
	MetaDataCache.cMut.RLock()
	MetaDataCache.pMut.RLock()
	MetaDataCache.sMut.RLock()
	MetaDataCache.HostPortInfo.mutex.RLock()
	GlobalNodeInfo.mutex.RLock()
	GlobalRsInfo.mut.RLock()
	GlobalServiceInfo.mut.RLock()
}

func RUnlockMetadataCache() {
	MetaDataCache.cMut.RUnlock()
	MetaDataCache.pMut.RUnlock()
	MetaDataCache.sMut.RUnlock()
	MetaDataCache.HostPortInfo.mutex.RUnlock()
	GlobalNodeInfo.mutex.RUnlock()
	GlobalRsInfo.mut.RUnlock()
	GlobalServiceInfo.mut.RUnlock()
}

func SetPreprocessingMetaDataCache(cache *K8sMetaDataCache, nodeMap *NodeMap, serviceMap *ServiceMap, rsMap *ReplicaSetMap) {
	for _, containersInfo := range cache.ContainerIdInfo {
		GlobalPodInfo.add(containersInfo.RefPodInfo)
	}
	GlobalNodeInfo = nodeMap
	GlobalServiceInfo = serviceMap
	GlobalRsInfo = rsMap
	MetaDataCache.ContainerIdInfo = cache.ContainerIdInfo
	MetaDataCache.HostPortInfo = cache.HostPortInfo
	MetaDataCache.IpContainerInfo = cache.IpContainerInfo
	MetaDataCache.IpServiceInfo = cache.IpServiceInfo
}

func InitK8sHandler(options ...Option) error {
	var retErr error
	once.Do(func() {
		k8sConfig := config{
			KubeAuthType:           AuthTypeKubeConfig,
			KubeConfigDir:          DefaultKubeConfigPath,
			GraceDeletePeriod:      DefaultGraceDeletePeriod,
			DSFConfig:              DefaultDSFConfig,
			MetaDataProviderConfig: DefaultMetaDataProviderConfig,
		}
		for _, option := range options {
			option(&k8sConfig)
		}

		if k8sConfig.DSFConfig.Enable {
			dsfEnable = true
			dsfConfig := k8sConfig.DSFConfig
			configServerClient := NewConfigServerClient(
				InitDSFEndpoint(dsfConfig.ConfigServerAddr, dsfConfig.InitEndpoint),
				UpdateDSFEndpoint(dsfConfig.ConfigServerAddr, dsfConfig.UpdateEndpoint))
			MetaDataCache.dsfRuleInfo.enableDebug = k8sConfig.DSFConfig.EnableDebug
			go MetaDataCache.dsfRuleInfo.ContinueSyncDSFRuleMapWithConfigServer(configServerClient.InitDSF, configServerClient.UpdateDSF, k8sConfig.DSFConfig.SyncInterval)
		}

		if k8sConfig.MetaDataProviderConfig.Enable {
			stopCh := make(chan struct{})
			if enableGraceDeletePeriod {
				go podDeleteLoop(10*time.Second, k8sConfig.GraceDeletePeriod, stopCh)
			}
			go func() {
				for {
					for i := 0; i < 3; i++ {
						err := k8sConfig.listAndWatchFromProvider()
						if err != nil {
							fmt.Printf("listAndWatch From Provider failled! Error: %d", err)
						}
					}

					// Failed after 3 times
					fmt.Printf("listAndWatch From Provider failled for 3 time, will retry after 1 minute")
					time.Sleep(1 * time.Minute)
				}
			}()
		} else {
			clientSet, err := initClientSet(string(k8sConfig.KubeAuthType), k8sConfig.KubeConfigDir)
			if err != nil {
				retErr = fmt.Errorf("cannot connect to kubernetes: %w", err)
				return
			}
			go NodeWatch(clientSet, k8sConfig.nodeEventHander)
			time.Sleep(1 * time.Second)
			go RsWatch(clientSet, k8sConfig.rsEventHander)
			time.Sleep(1 * time.Second)
			go ServiceWatch(clientSet, k8sConfig.serviceEventHander)
			time.Sleep(1 * time.Second)
			go PodWatch(clientSet, k8sConfig.GraceDeletePeriod, k8sConfig.podEventHander)
			time.Sleep(1 * time.Second)
			KubeClient = clientSet
		}
	})
	return retErr
}

func initClientSet(authType string, dir string) (*k8s.Clientset, error) {
	return makeClient(APIConfig{
		AuthType:     AuthType(authType),
		AuthFilePath: dir,
	})
}

// MakeClient can take configuration if needed for other types of auth
func makeClient(apiConf APIConfig) (*k8s.Clientset, error) {
	if err := apiConf.Validate(); err != nil {
		return nil, err
	}

	authConf, err := createRestConfig(apiConf)
	if err != nil {
		return nil, err
	}

	client, err := k8s.NewForConfig(authConf)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// createRestConfig creates an Kubernetes API config from user configuration.
func createRestConfig(apiConf APIConfig) (*rest.Config, error) {
	var authConf *rest.Config
	var err error

	authType := apiConf.AuthType

	var k8sHost string
	if authType != AuthTypeKubeConfig {
		host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
		if len(host) == 0 || len(port) == 0 {
			return nil, fmt.Errorf("unable to load k8s config, KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT must be defined")
		}
		k8sHost = "https://" + net.JoinHostPort(host, port)
	}

	switch authType {
	case AuthTypeKubeConfig:
		if apiConf.AuthFilePath == "" {
			apiConf.AuthFilePath = DefaultKubeConfigPath
		}
		loadingRules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: apiConf.AuthFilePath}
		configOverrides := &clientcmd.ConfigOverrides{}
		authConf, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			loadingRules, configOverrides).ClientConfig()

		if err != nil {
			return nil, fmt.Errorf("error connecting to k8s with auth_type=%s: %w", AuthTypeKubeConfig, err)
		}
	case AuthTypeNone:
		authConf = &rest.Config{
			Host: k8sHost,
		}
		authConf.Insecure = true
	case AuthTypeServiceAccount:
		// This should work for most clusters but other auth types can be added
		authConf, err = rest.InClusterConfig()
		if err != nil {
			return nil, err
		}
	}

	authConf.WrapTransport = func(rt http.RoundTripper) http.RoundTripper {
		// Don't use system proxy settings since the API is local to the
		// cluster
		if t, ok := rt.(*http.Transport); ok {
			t.Proxy = nil
		}
		return rt
	}

	return authConf, nil
}
