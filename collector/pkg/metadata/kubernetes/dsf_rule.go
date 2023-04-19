package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	docker "github.com/docker/docker/client"
	corev1 "k8s.io/api/core/v1"
)

const DEFAULT_MAX_UPDATE_CHAN_SIZE = 32
const DEFAULT_UPDATE_QUEUE_SIZE = 64

const DOCKER = "docker"
const CONTAINERD = "containerd"

var runtimeService RuntimeServiceShim

type DSFRuleMap struct {
	dstRules RuleMap

	localRuleMap    RuleMap
	updateRuleQueue []*DSFRule
	// timestamp
	lastUpdateTimestamp int64
	// remoteState
	remoteNeedInit bool

	localRuleMux  sync.RWMutex
	globalRuleMux sync.RWMutex

	hostIp string

	stopCh     chan struct{}
	ticker     *time.Ticker
	updateChan chan *DSFRule

	enableDebug bool
}

func newDSFRuleMap() *DSFRuleMap {
	if runtime, find := os.LookupEnv("RUNTIME"); find {
		switch runtime {
		case DOCKER:
			cli, err := docker.NewClientWithOpts(docker.FromEnv, docker.WithAPIVersionNegotiation())
			if err != nil {
				fmt.Printf("Failed to set up docker client , will not use dsf rule! err: %v \n", err)
			}
			runtimeService = &DockerClient{
				cli: cli,
				ctx: context.Background(),
			}
		}
	} else {
		cli, err := docker.NewClientWithOpts(docker.FromEnv, docker.WithAPIVersionNegotiation())
		if err != nil {
			fmt.Printf("Failed to set up docker client , will not use dsf rule! err: %v \n", err)
		}
		runtimeService = &DockerClient{
			cli: cli,
			ctx: context.Background(),
		}
	}

	return &DSFRuleMap{
		dstRules:        make(RuleMap),
		localRuleMap:    make(RuleMap),
		updateRuleQueue: make([]*DSFRule, 0, DEFAULT_UPDATE_QUEUE_SIZE),
		remoteNeedInit:  true,
		hostIp:          getHostIpFromEnv(),
		stopCh:          make(chan struct{}),
		updateChan:      make(chan *DSFRule, DEFAULT_MAX_UPDATE_CHAN_SIZE),
		enableDebug:     false,
	}
}

type RuleMap map[NodeIp]map[Port]*ContainerNetInfo

type Port uint32

type ContainerNetInfo struct {
	ContainerId string `json:"containerId"`
	PrivatePort Port   `json:"privatePort"`
	IsDeleted   bool   `json:"isDeleted"`

	// Will not transfer
	ContainerRef *K8sContainerInfo `json:"-"`
}

type DSFRule struct {
	Key       DSFRuleKey       `json:"key"`
	Container ContainerNetInfo `json:"container"`
	remote    bool
}

type NodeIp string
type DSFRuleKey struct {
	NodeIp     NodeIp `json:"nodeIp"`
	PublicPort Port   `json:"publicPort"`
}

type DSFSyncRequest struct {
	HostIp              string     `json:"hostIp"`
	UpdateRule          []*DSFRule `json:"updateRule"`
	LastUpdateTimestamp int64      `json:"lastUpdateTimestamp"`
}

type Response struct {
	Msg  string          `json:"msg"`
	Code int             `json:"code"`
	Data DSFSyncResponse `json:"data"`
}

type DSFSyncResponse struct {
	Results  []*DSFRule `json:"results"`
	NeedInit bool       `json:"needInit"`
	// timestamp
	UpdateTimestamp int64 `json:"updateTimestamp"`
}

func (d *DSFRuleMap) createAndAddRule(publicPort Port, containerRef *K8sContainerInfo, portInfo corev1.ContainerPort) {
	rule := &DSFRule{
		Key: DSFRuleKey{
			NodeIp(hostIp),
			publicPort,
		},
		Container: ContainerNetInfo{
			ContainerId:  containerRef.ContainerId,
			PrivatePort:  Port(portInfo.ContainerPort),
			ContainerRef: containerRef,
		},
	}
	d.updateChan <- rule
}

func (d *DSFRuleMap) deleteAndAddRule(publicPorts ...Port) {
	for _, publicPort := range publicPorts {
		rule := &DSFRule{
			Key: DSFRuleKey{
				NodeIp(hostIp),
				publicPort,
			},
			Container: ContainerNetInfo{
				IsDeleted: true,
			},
		}
		d.updateChan <- rule
	}
}

func (d *DSFRuleMap) UpdateRemoteDSFRule(rules ...*DSFRule) {
	for i := len(rules); i > 0; i-- {
		rules[i-1].remote = true
		d.updateChan <- rules[i-1]
	}
}

func (d *DSFRuleMap) SearchByPublicPortAndNodeIp(publicPort Port, nodeIp NodeIp) (*ContainerNetInfo, bool) {
	d.globalRuleMux.RLock()
	defer d.globalRuleMux.RUnlock()
	if portMap, ok := d.dstRules[nodeIp]; ok {
		res, ok := portMap[publicPort]
		return res, ok
	} else {
		return nil, false
	}
}

func (d *DSFRuleMap) SearchLocalPublicPortByPodIpAndPrivatePort(privatePort Port, podIp string) (Port, bool) {
	d.localRuleMux.RLock()
	defer d.localRuleMux.RUnlock()
	for _, portMap := range d.localRuleMap {
		for publicPort, info := range portMap {
			if info.ContainerRef.RefPodInfo.Ip == podIp && info.PrivatePort == privatePort {
				return publicPort, true
			}
		}
	}
	return Port(0), false
}

func (d *DSFRuleMap) SearchLocalPublicPortByContainerId(containerId string) ([]Port, bool) {
	ports := make([]Port, 0)
	find := false
	d.localRuleMux.RLock()
	defer d.localRuleMux.RUnlock()
	for _, portMap := range d.localRuleMap {
		for publicPort, info := range portMap {
			if info.ContainerRef.ContainerId == containerId {
				ports = append(ports, Port(publicPort))
				find = true
			}
		}
	}
	return ports, find
}

func (d *DSFRuleMap) UpdateLocalDSFRule(rules ...*DSFRule) {
	for i := 0; i < len(rules); i++ {
		rules[i].remote = false
		d.updateChan <- rules[i]
	}
}

func (d *DSFRuleMap) updateDSFRule(rule *DSFRule) {
	if rule.remote {
		if containerRef, ok := MetaDataCache.GetByContainerId(rule.Container.ContainerId); ok {
			rule.Container.ContainerRef = containerRef
		}
	} else {
		d.updateLocalMap(rule)
	}

	// update global rulesMap
	d.globalRuleMux.Lock()
	defer d.globalRuleMux.Unlock()
	d.dstRules.acceptRule(rule)
}

func (r RuleMap) acceptRule(rule *DSFRule) {
	if rule.Container.IsDeleted {
		if portMap, ok := r[rule.Key.NodeIp]; ok {
			delete(portMap, rule.Key.PublicPort)
		}
	} else {
		if portMap, ok := r[rule.Key.NodeIp]; ok {
			portMap[rule.Key.PublicPort] = &rule.Container
		} else {
			portMap = make(map[Port]*ContainerNetInfo)
			portMap[rule.Key.PublicPort] = &rule.Container
			r[rule.Key.NodeIp] = portMap
		}
	}
}

func (d *DSFRuleMap) updateLocalMap(rule *DSFRule) {
	d.localRuleMux.Lock()
	defer d.localRuleMux.Unlock()
	d.updateRuleQueue = append(d.updateRuleQueue, rule)
	d.localRuleMap.acceptRule(rule)
}

// SyncWithConfigServer sending Request to ConfigServer to get the changes of ruleMap
func (d *DSFRuleMap) syncWithConfigServer(sync SyncDSFRule, init InitDSFRule) {
	req := &DSFSyncRequest{
		HostIp:              d.hostIp,
		LastUpdateTimestamp: d.lastUpdateTimestamp,
	}

	if d.remoteNeedInit {
		req.UpdateRule = ConvertMapToRules(d.localRuleMap)
	} else {
		req.UpdateRule = d.updateRuleQueue
	}

	d.updateRuleQueue = make([]*DSFRule, 0, DEFAULT_UPDATE_QUEUE_SIZE)
	var resp *DSFSyncResponse
	if d.remoteNeedInit {
		resp = init(req)
	} else {
		resp = sync(req)
	}

	if resp != nil {
		d.UpdateRemoteDSFRule(resp.Results...)
		d.remoteNeedInit = resp.NeedInit
		d.lastUpdateTimestamp = resp.UpdateTimestamp
	} else {
		d.remoteNeedInit = true
	}
}

func (d *DSFRuleMap) ContinueSyncDSFRuleMapWithConfigServer(init InitDSFRule, sync SyncDSFRule, syncInterval time.Duration) {
	d.ticker = time.NewTicker(syncInterval)
	debugCounter := 0
	for {
		select {
		case <-d.stopCh:
			return
		case <-d.ticker.C:
			if debugCounter > 3 {
				debugCounter = 0
				fmt.Printf("[ DEBUG ] DSFMap: \n%s", d)
			} else if d.enableDebug {
				debugCounter++
			}
			d.syncWithConfigServer(sync, init)
		case newRule := <-d.updateChan:
			d.updateDSFRule(newRule)
		}
	}
}

func (d *DSFRuleMap) String() string {
	var res strings.Builder
	d.globalRuleMux.RLock()
	defer d.globalRuleMux.RUnlock()
	for nodeIp, portMap := range d.dstRules {
		res.WriteString(fmt.Sprintf("[Node]: %s \n", nodeIp))
		for publicPort, ContainerInfo := range portMap {
			res.WriteString(fmt.Sprintf("\t \"%d\" : \"%s:%d\"\n", publicPort, ContainerInfo.ContainerId, ContainerInfo.PrivatePort))
		}
	}
	return res.String()
}

type PortMap map[Port][]Port

type RuntimeServiceShim interface {
	GetPortMappingByContainerId(containerId string) (PortMap, error)
}

func CreateDSFRuleByContainerPrivatePorts(
	containerRef *K8sContainerInfo,
	privatePorts []Port,
	portMap PortMap,
	hostIP NodeIp,
) ([]*DSFRule, error) {
	rules := make([]*DSFRule, 0)
	for _, privatePort := range privatePorts {
		containerNetInfo := ContainerNetInfo{
			ContainerId:  containerRef.ContainerId,
			PrivatePort:  Port(privatePort),
			IsDeleted:    false,
			ContainerRef: containerRef,
		}
		if publicPorts, ok := portMap[privatePort]; ok {
			for _, publicPort := range publicPorts {
				rule := &DSFRule{
					DSFRuleKey{hostIP, Port(publicPort)},
					containerNetInfo,
					false,
				}
				rules = append(rules, rule)
			}
		}
	}
	return rules, nil
}

type DockerClient struct {
	cli *docker.Client
	ctx context.Context
}

// GetPortMappingByContainerId use the field `NetworkSettings.Ports` in `docker.ContainerInspect` Api
func (c *DockerClient) GetPortMappingByContainerId(containerId string) (PortMap, error) {
	res, err := c.cli.ContainerInspect(c.ctx, containerId)
	if err != nil {
		return nil, err
	}
	portMap := make(PortMap)
	portsInfo := res.HostConfig.PortBindings
	if len(portsInfo) == 0 {
		pauseId, err := c.getPauseContainerId(containerId)
		if pauseId == "" {
			return nil, nil
		}
		if err != nil {
			return nil, err
		} else {
			res, err := c.cli.ContainerInspect(c.ctx, pauseId)
			if err != nil {
				return nil, err
			}
			portsInfo = res.HostConfig.PortBindings
		}
	}
	for privatePortStr, publicPorts := range portsInfo {
		var privatePort int
		portStrs := PortBinding.FindStringSubmatch(string(privatePortStr))
		if len(portStrs) < 2 {
			continue
		}
		if privatePort, err = strconv.Atoi(portStrs[1]); err != nil {
			continue
		}
		ports := make([]Port, 0, len(publicPorts))
		for i := 0; i < len(publicPorts); i++ {
			var publicPort int
			if publicPort, err = strconv.Atoi(publicPorts[i].HostPort); err != nil {
				continue
			}
			ports = append(ports, Port(publicPort))
		}
		portMap[Port(privatePort)] = ports
	}
	return portMap, nil
}

func (c *DockerClient) getPauseContainerId(containerId string) (string, error) {
	res, err := c.cli.ContainerInspect(c.ctx, containerId)
	if err != nil {
		return "", err
	}
	regexRes := SandBoxIdInNetworkMode.FindStringSubmatch(string(res.HostConfig.NetworkMode))
	if len(regexRes) > 1 {
		return regexRes[1], nil
	} else {
		return "", nil
	}
}

func ConvertRulesToMap(rules []DSFRule) (ruleMap RuleMap) {
	ruleMap = make(RuleMap)
	for i := 0; i < len(rules); i++ {
		ruleMap.acceptRule(&rules[i])
	}
	return
}

func ConvertMapToRules(ruleMap RuleMap) (rules []*DSFRule) {
	rules = make([]*DSFRule, 0, len(ruleMap))
	for nodeIp, v := range ruleMap {
		for publicPort, v := range v {
			rules = append(rules, &DSFRule{DSFRuleKey{nodeIp, publicPort}, *v, false})
		}
	}
	return
}

type SyncDSFRule func(request *DSFSyncRequest) *DSFSyncResponse

type InitDSFRule func(request *DSFSyncRequest) *DSFSyncResponse

type ConfigServerClient struct {
	client http.Client

	initDSFEndpoint   string
	updateDSFEndPoint string
}

func NewConfigServerClient(opts ...WithOptions) ConfigServerClient {
	httpClient := createHTTPClient()
	configServerClient := ConfigServerClient{
		client: *httpClient,
	}
	for _, opt := range opts {
		opt(&configServerClient)
	}
	return configServerClient
}

type WithOptions func(*ConfigServerClient)

func InitDSFEndpoint(addr string, endpoint string) WithOptions {
	return func(c *ConfigServerClient) {
		c.initDSFEndpoint = fmt.Sprintf("%s%s", addr, endpoint)
	}
}

func UpdateDSFEndpoint(addr string, endpoint string) WithOptions {
	return func(c *ConfigServerClient) {
		c.updateDSFEndPoint = fmt.Sprintf("%s%s", addr, endpoint)
	}
}

func (c *ConfigServerClient) InitDSF(request *DSFSyncRequest) *DSFSyncResponse {
	return c.postDSFRequest(request, c.initDSFEndpoint)
}

func (c *ConfigServerClient) UpdateDSF(request *DSFSyncRequest) *DSFSyncResponse {
	return c.postDSFRequest(request, c.updateDSFEndPoint)
}

func (c *ConfigServerClient) postDSFRequest(request *DSFSyncRequest, endpoint string) *DSFSyncResponse {
	msgBytes, _ := json.Marshal(request)
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(msgBytes))
	if err != nil {
		log.Printf("error occurred when creating post request to %s:%+v\n", endpoint, err)
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		log.Printf("error occurred when posting to %s:%+v\n", endpoint, err)
		return nil
	}
	var dsfResp Response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("error occurred when posting to %s:%+v\n", endpoint, err)
		return nil
	}
	err = json.Unmarshal(body, &dsfResp)
	if err != nil {
		log.Printf("error occurred when posting to %s:%+v\n", endpoint, err)
		return nil
	}
	return &dsfResp.Data
}

var SandBoxIdInNetworkMode = regexp.MustCompile("container:([a-z0-9]+)")

var PortBinding = regexp.MustCompile("([0-9]+)/tcp")

const (
	MaxIdleConns        int = 100
	MaxIdleConnsPerHost int = 100
	IdleConnTimeout     int = 90
)

func createHTTPClient() *http.Client {
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:        MaxIdleConns,
			MaxIdleConnsPerHost: MaxIdleConnsPerHost,
			IdleConnTimeout:     time.Duration(IdleConnTimeout) * time.Second,
		},
	}
	return client
}
