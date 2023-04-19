package kubernetes

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/docker/docker/client"
	dockerclient "github.com/docker/docker/client"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/cri-api/pkg/apis/runtime/v1"
	"k8s.io/kubernetes/pkg/kubelet/cri/remote"
)

var TEST_INIT_ENDPOINTS = "http://127.0.0.1:8081/initDSF"
var TEST_UPDATE_ENDPOINTS = "http://127.0.0.1:8081/updateDSF"

// DSFRemoteCenter -> initDSF
// 				   -> updateDSF

type DSFRemoteCenter struct {
	dstRules RuleMap

	updateRuleQueue []*UpdateQuestWithTimestamp

	updateRuleMux sync.RWMutex
	globalRuleMux sync.RWMutex
}

type UpdateQuestWithTimestamp struct {
	updateRuleQueue []*DSFRule
	hostIp          string
	updateTime      int64
}

func (c *DSFRemoteCenter) InitDSF(req *DSFSyncRequest) *DSFSyncResponse {
	timestamp := time.Now().Unix()
	c.globalRuleMux.Lock()
	resp := &DSFSyncResponse{
		Results:         ConvertMapToRules(c.dstRules),
		NeedInit:        false,
		UpdateTimestamp: timestamp,
	}
	portMap := make(map[Port]*ContainerNetInfo)
	for _, rule := range req.UpdateRule {
		if rule != nil {
			portMap[rule.Key.PublicPort] = &rule.Container
		}
	}
	c.dstRules[NodeIp(req.HostIp)] = portMap
	c.globalRuleMux.Unlock()

	c.updateRuleMux.Lock()
	c.updateRuleQueue = append(c.updateRuleQueue, &UpdateQuestWithTimestamp{
		req.UpdateRule,
		req.HostIp,
		timestamp,
	})
	c.updateRuleMux.Unlock()
	return resp
}

func (c *DSFRemoteCenter) UpdateDSF(req *DSFSyncRequest) *DSFSyncResponse {
	timestamp := time.Now().Unix()
	needInit, resp := c.checkInit(req, timestamp)
	if needInit {
		return resp
	}

	c.updateRuleMux.Lock()
	needUpdate := make([]*DSFRule, 0)
	for i := len(c.updateRuleQueue); i > 0; i-- {
		index := i - 1
		if c.updateRuleQueue[index].updateTime < req.LastUpdateTimestamp {
			break
		}
		if c.updateRuleQueue[index].hostIp == req.HostIp {
			continue
		}
		needUpdate = append(needUpdate, c.updateRuleQueue[index].updateRuleQueue...)
	}

	if len(req.UpdateRule) > 0 {
		c.updateRuleQueue = append(c.updateRuleQueue, &UpdateQuestWithTimestamp{
			req.UpdateRule,
			req.HostIp,
			timestamp,
		})
	}
	c.updateRuleMux.Unlock()

	c.globalRuleMux.Lock()
	for _, rule := range req.UpdateRule {
		c.dstRules.acceptRule(rule)
	}
	c.globalRuleMux.Unlock()

	return &DSFSyncResponse{
		needUpdate,
		false,
		timestamp,
	}
}

func (c *DSFRemoteCenter) checkInit(req *DSFSyncRequest, timestamp int64) (bool, *DSFSyncResponse) {
	c.globalRuleMux.RLock()
	defer c.globalRuleMux.RUnlock()
	if _, find := c.dstRules[NodeIp(req.HostIp)]; !find {
		return true, &DSFSyncResponse{
			nil,
			true,
			timestamp,
		}
	}
	return false, nil
}

func TestDockershim(t *testing.T) {
	srv, err := remote.NewRemoteRuntimeService("unix:///var/run/dockershim.sock", 10*time.Second)
	assert.NoError(t, err, "Failed to get connected with dockershim")
	containers, err := srv.ListContainers(&v1.ContainerFilter{State: &v1.ContainerStateValue{State: v1.ContainerState_CONTAINER_RUNNING}})
	assert.NoError(t, err, "Failed to list containers managed by dockershim")

	ctx := context.Background()
	cli, err := dockerclient.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	dockerClient := &DockerClient{
		cli: cli,
		ctx: ctx,
	}

	for _, container := range containers {
		portMap, err := dockerClient.GetPortMappingByContainerId(container.Id)
		assert.NoError(t, err, "Failed to get PortMap")
		// Inspect
		fmt.Printf("ContainerId:%v\tPortMap%+v\n", container.Id, portMap)
	}
	assert.NoError(t, err, "Failed to get connected with dockerd")
}

func TestSyncWithRemote(t *testing.T) {
	remoteCenter := &DSFRemoteCenter{
		dstRules:        make(RuleMap),
		updateRuleQueue: make([]*UpdateQuestWithTimestamp, 0),
	}

	dsfMap := newDSFRuleMap()
	dsfMap.hostIp = "1.1.1.1"

	dsfMap2 := newDSFRuleMap()
	dsfMap2.hostIp = "2.2.2.2"

	go dsfMap.ContinueSyncDSFRuleMapWithConfigServer(remoteCenter.InitDSF, remoteCenter.UpdateDSF, 1*time.Second)
	go dsfMap2.ContinueSyncDSFRuleMapWithConfigServer(remoteCenter.InitDSF, remoteCenter.UpdateDSF, 1*time.Second)

	dsfMap.updateChan <- &DSFRule{
		Key:       DSFRuleKey{"1.1.1.1", 58080},
		Container: ContainerNetInfo{"abcdefg", 8080, false, nil},
		remote:    false,
	}

	dsfMap2.updateChan <- &DSFRule{
		Key:       DSFRuleKey{"2.2.2.2", 58080},
		Container: ContainerNetInfo{"a1b2c3d4", 8080, false, nil},
		remote:    false,
	}

	time.Sleep(2 * time.Second)

	assert.Equal(t, 2, len(remoteCenter.dstRules))
	assert.Equal(t, 1, len(remoteCenter.dstRules["1.1.1.1"]))
	assert.Equal(t, 1, len(remoteCenter.dstRules["2.2.2.2"]))

	dsfMap.updateChan <- &DSFRule{
		Key:       DSFRuleKey{"1.1.1.1", 58081},
		Container: ContainerNetInfo{"a1b2c3d4", 8081, false, nil},
		remote:    false,
	}

	time.Sleep(3 * time.Second)

	assert.Equal(t, 2, len(remoteCenter.dstRules))
	assert.Equal(t, 2, len(remoteCenter.dstRules["1.1.1.1"]))
	assert.Equal(t, 1, len(remoteCenter.dstRules["2.2.2.2"]))

	assert.Equal(t, 2, len(dsfMap.dstRules))
	assert.Equal(t, 2, len(dsfMap.dstRules["1.1.1.1"]))
	assert.Equal(t, 2, len(dsfMap2.dstRules))
	assert.Equal(t, 2, len(dsfMap2.dstRules["1.1.1.1"]))

	// agent2 restart
	dsfMap2.stopCh <- struct{}{}
	dsfMap2 = newDSFRuleMap()
	dsfMap2.hostIp = "2.2.2.2"

	go dsfMap2.ContinueSyncDSFRuleMapWithConfigServer(remoteCenter.InitDSF, remoteCenter.UpdateDSF, 1*time.Second)

	dsfMap2.updateChan <- &DSFRule{
		Key:       DSFRuleKey{"2.2.2.2", 58080},
		Container: ContainerNetInfo{"a1b2c3d4", 8080, false, nil},
		remote:    false,
	}

	time.Sleep(3 * time.Second)

	assert.Equal(t, 2, len(remoteCenter.dstRules))
	assert.Equal(t, 2, len(remoteCenter.dstRules["1.1.1.1"]))
	assert.Equal(t, 1, len(remoteCenter.dstRules["2.2.2.2"]))

	assert.Equal(t, 2, len(dsfMap.dstRules))
	assert.Equal(t, 2, len(dsfMap.dstRules["1.1.1.1"]))
	assert.Equal(t, 2, len(dsfMap2.dstRules))
	assert.Equal(t, 2, len(dsfMap2.dstRules["1.1.1.1"]))

	// configServer restart
	remoteCenter.globalRuleMux.Lock()
	remoteCenter.dstRules = make(RuleMap)
	remoteCenter.globalRuleMux.Unlock()

	remoteCenter.updateRuleMux.Lock()
	remoteCenter.updateRuleQueue = make([]*UpdateQuestWithTimestamp, 0)
	remoteCenter.updateRuleMux.Unlock()

	time.Sleep(5 * time.Second)

	assert.Equal(t, 2, len(remoteCenter.dstRules))
	assert.Equal(t, 2, len(remoteCenter.dstRules["1.1.1.1"]))
	assert.Equal(t, 1, len(remoteCenter.dstRules["2.2.2.2"]))

	assert.Equal(t, 2, len(dsfMap.dstRules))
	assert.Equal(t, 2, len(dsfMap.dstRules["1.1.1.1"]))
	assert.Equal(t, 2, len(dsfMap2.dstRules))
	assert.Equal(t, 2, len(dsfMap2.dstRules["1.1.1.1"]))

	fmt.Println("ok")
}

func TestDockerClient_getPauseContainerId(t *testing.T) {
	srv, err := remote.NewRemoteRuntimeService("unix:///var/run/dockershim.sock", 10*time.Second)
	assert.NoError(t, err, "Failed to get connected with dockershim")
	containers, err := srv.ListContainers(&v1.ContainerFilter{State: &v1.ContainerStateValue{State: v1.ContainerState_CONTAINER_RUNNING}})
	assert.NoError(t, err, "Failed to list containers managed by dockershim")

	ctx := context.Background()
	cli, err := dockerclient.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	dockerClient := &DockerClient{
		cli: cli,
		ctx: ctx,
	}

	for _, container := range containers {
		pauseContainerId, err := dockerClient.getPauseContainerId(container.Id)
		assert.NoError(t, err, "Failed to get PortMap")
		// Inspect
		fmt.Printf("ContainerId:%v\tPauseId:%+v\n", container.Id, pauseContainerId)
	}
	assert.NoError(t, err, "Failed to get connected with dockerd")
}

// func TestRegex(t *testing.T) {
// 	var SandBoxIdInNetworkMode = regexp.MustCompile("container:([a-z0-9]+)")
// 	data := SandBoxIdInNetworkMode.FindStringSubmatch("\"container:11caa0bb23c9b16f176e974468ca381c14f16746c863aff6eaf0d54afb276065\"")
// 	fmt.Println(data)
// }

func TestSyncWithCongfigServer(t *testing.T) {
	configServerClient := NewConfigServerClient(
		InitDSFEndpoint("http://10.10.116.76:8888", "/hcmine/config/dsfInit"),
		UpdateDSFEndpoint("http://10.10.116.76:8888", "/hcmine/config/dsfUpdate"))

	dsfMap := newDSFRuleMap()
	dsfMap.hostIp = "1.1.1.1"

	dsfMap2 := newDSFRuleMap()
	dsfMap2.hostIp = "2.2.2.2"

	go dsfMap.ContinueSyncDSFRuleMapWithConfigServer(configServerClient.InitDSF, configServerClient.UpdateDSF, 2*time.Second)
	go dsfMap2.ContinueSyncDSFRuleMapWithConfigServer(configServerClient.InitDSF, configServerClient.UpdateDSF, 2*time.Second)

	dsfMap.updateChan <- &DSFRule{
		Key:       DSFRuleKey{"1.1.1.1", 58080},
		Container: ContainerNetInfo{"abcdefg", 8080, false, nil},
		remote:    false,
	}

	dsfMap2.updateChan <- &DSFRule{
		Key:       DSFRuleKey{"2.2.2.2", 58080},
		Container: ContainerNetInfo{"a1b2c3d4", 8080, false, nil},
		remote:    false,
	}

	time.Sleep(10 * time.Second)

	assert.Equal(t, 2, len(dsfMap.dstRules))

	dsfMap.updateChan <- &DSFRule{
		Key:       DSFRuleKey{"1.1.1.1", 58081},
		Container: ContainerNetInfo{"a1b2c3d4", 8081, false, nil},
		remote:    false,
	}

	time.Sleep(10 * time.Second)

	// assert.Equal(t, 2, len(configServerClient.dstRules))
	// assert.Equal(t, 2, len(configServerClient.dstRules["1.1.1.1"]))
	// assert.Equal(t, 1, len(configServerClient.dstRules["2.2.2.2"]))

	assert.Equal(t, 2, len(dsfMap.dstRules))
	assert.Equal(t, 1, len(dsfMap.dstRules["2.2.2.2"]))
	assert.Equal(t, 2, len(dsfMap2.dstRules))
	assert.Equal(t, 2, len(dsfMap2.dstRules["1.1.1.1"]))

	// agent2 restart
	dsfMap2.stopCh <- struct{}{}
	dsfMap2 = newDSFRuleMap()
	dsfMap2.hostIp = "2.2.2.2"

	go dsfMap2.ContinueSyncDSFRuleMapWithConfigServer(configServerClient.InitDSF, configServerClient.UpdateDSF, 1*time.Second)

	dsfMap2.updateChan <- &DSFRule{
		Key:       DSFRuleKey{"2.2.2.2", 58080},
		Container: ContainerNetInfo{"a1b2c3d4", 8080, false, nil},
		remote:    false,
	}

	time.Sleep(10 * time.Second)

	// assert.Equal(t, 2, len(configServerClient.dstRules))
	// assert.Equal(t, 2, len(configServerClient.dstRules["1.1.1.1"]))
	// assert.Equal(t, 1, len(configServerClient.dstRules["2.2.2.2"]))

	assert.Equal(t, 2, len(dsfMap.dstRules))
	assert.Equal(t, 1, len(dsfMap.dstRules["2.2.2.2"]))
	assert.Equal(t, 2, len(dsfMap2.dstRules))
	assert.Equal(t, 2, len(dsfMap2.dstRules["1.1.1.1"]))

	select {}
}
