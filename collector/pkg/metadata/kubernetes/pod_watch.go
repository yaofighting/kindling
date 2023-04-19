package kubernetes

import (
	"fmt"
	"os"
	_ "path/filepath"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	_ "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	_ "k8s.io/client-go/tools/clientcmd"
	_ "k8s.io/client-go/util/homedir"

	"github.com/Kindling-project/kindling/collector/pkg/compare"
)

func init() {
	hostIp = getHostIpFromEnv()
}

type podMap struct {
	// namespace:
	//   podName: podInfo{}
	Info  map[string]map[string]*K8sPodInfo
	mutex sync.RWMutex
}

var GlobalPodInfo = newPodMap()
var hostIp string
var enableGraceDeletePeriod bool = true

func newPodMap() *podMap {
	return &podMap{
		Info:  make(map[string]map[string]*K8sPodInfo),
		mutex: sync.RWMutex{},
	}
}

func (m *podMap) add(info *K8sPodInfo) {
	m.mutex.Lock()
	podInfoMap, ok := m.Info[info.Namespace]
	if !ok {
		podInfoMap = make(map[string]*K8sPodInfo)
	}
	podInfoMap[info.PodName] = info
	m.Info[info.Namespace] = podInfoMap
	m.mutex.Unlock()
}

func (m *podMap) delete(namespace string, name string) {
	m.mutex.Lock()
	podInfoMap, ok := m.Info[namespace]
	if ok {
		delete(podInfoMap, name)
	}
	m.mutex.Unlock()
}

func (m *podMap) get(namespace string, name string) (*K8sPodInfo, bool) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	podInfoMap, ok := m.Info[namespace]
	if !ok {
		return nil, false
	}
	podInfo, ok := podInfoMap[name]
	if !ok {
		return nil, false
	}
	return podInfo, true
}

// getPodsMatchSelectors gets K8sPodInfo(s) whose labels match with selectors in such namespace.
// Return empty slice if not found. Note there may be multiple match.
func (m *podMap) getPodsMatchSelectors(namespace string, selectors map[string]string) []*K8sPodInfo {
	retPodInfoSlice := make([]*K8sPodInfo, 0)
	if len(selectors) == 0 {
		return retPodInfoSlice
	}
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	podInfoMap, ok := m.Info[namespace]
	if !ok {
		return retPodInfoSlice
	}
	for _, podInfo := range podInfoMap {
		if SelectorsMatchLabels(selectors, podInfo.Labels) {
			retPodInfoSlice = append(retPodInfoSlice, podInfo)
		}
	}
	return retPodInfoSlice
}

func PodWatch(clientSet *kubernetes.Clientset, graceDeletePeriod time.Duration, handler cache.ResourceEventHandler) {
	if graceDeletePeriod == 0 {
		enableGraceDeletePeriod = false
	}

	stopper := make(chan struct{})
	defer close(stopper)

	factory := informers.NewSharedInformerFactory(clientSet, 0)
	podInformer := factory.Core().V1().Pods()
	informer := podInformer.Informer()
	defer runtime.HandleCrash()

	// Start informer, list & watch
	go factory.Start(stopper)

	if !cache.WaitForCacheSync(stopper, informer.HasSynced) {
		runtime.HandleError(fmt.Errorf("timed out waiting for caches to sync"))
		return
	}
	if enableGraceDeletePeriod {
		go podDeleteLoop(10*time.Second, graceDeletePeriod, stopper)
	}

	if handler == nil {
		informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc:    PodAdd,
			UpdateFunc: PodUpdate,
			DeleteFunc: PodDelete,
		})
	} else {
		informer.AddEventHandler(handler)
	}
	// TODO: use workqueue to avoid blocking
	<-stopper
}

func PodAdd(obj interface{}) {
	pod := obj.(*corev1.Pod)

	// Find the controller workload of the pod
	rsUpdateMutex.RLock()
	workloadTypeTmp, workloadNameTmp := getControllerKindName(pod)
	rsUpdateMutex.RUnlock()

	// Find one of the services of the pod
	serviceInfoSlice := GlobalServiceInfo.GetServiceMatchLabels(pod.Namespace, pod.Labels)
	var serviceInfo *K8sServiceInfo
	if len(serviceInfoSlice) == 0 {
		serviceInfo = nil
	} else {
		// When span target is a kind of service, workload should also be filled in case to display
		// the real topology in model level. Service is considered as abstract level, instead.
		// So here the information of workload is assigned to serviceInfo.
		for _, service := range serviceInfoSlice {
			service.WorkloadKind = workloadTypeTmp
			service.WorkloadName = workloadNameTmp
		}
		// Only one of the matched services is cared, here we get the first one
		serviceInfo = serviceInfoSlice[0]
	}

	var cachePodInfo = &K8sPodInfo{
		UID:           string(pod.UID),
		Ip:            pod.Status.PodIP,
		Namespace:     pod.Namespace,
		PodName:       pod.Name,
		Ports:         make([]int32, 0),
		HostPorts:     make([]int32, 0),
		ContainerIds:  make([]string, 0, 2),
		Labels:        pod.Labels,
		WorkloadKind:  workloadTypeTmp,
		WorkloadName:  workloadNameTmp,
		NodeName:      pod.Spec.NodeName,
		NodeAddress:   pod.Status.HostIP,
		isHostNetwork: pod.Spec.HostNetwork,
		ServiceInfo:   serviceInfo,
	}

	// Add containerId map
	var portMap PortMap
	var err error
	for _, containerStatus := range pod.Status.ContainerStatuses {
		shortenContainerId := TruncateContainerId(containerStatus.ContainerID)
		if shortenContainerId == "" {
			continue
		}
		cachePodInfo.ContainerIds = append(cachePodInfo.ContainerIds, shortenContainerId)
		containerInfo := &K8sContainerInfo{
			ContainerId: shortenContainerId,
			Name:        containerStatus.Name,
			RefPodInfo:  cachePodInfo,
		}
		MetaDataCache.AddByContainerId(shortenContainerId, containerInfo)
		if dsfEnable &&
			portMap == nil &&
			pod.Status.HostIP == hostIp &&
			runtimeService != nil &&
			pod.Status.Phase == corev1.PodRunning {
			portMap, err = runtimeService.GetPortMappingByContainerId(TruncateComplateContainerId(containerStatus.ContainerID))
			if err != nil {
				fmt.Printf("Failed to get portMap for container: %v,err is : %v\n", TruncateContainerId(containerStatus.ContainerID), err)
			}
		}
		if len(portMap) > 0 {
			for _, containerSpec := range pod.Spec.Containers {
				if containerSpec.Name == containerStatus.Name {
					MetaDataCache.AddDSFRuleByContainerPorts(containerSpec.Ports, portMap, containerInfo)
					break
				}
			}
		}
	}

	// Add pod IP and port map
	if len(pod.Status.PodIP) > 0 {
		for _, tmpContainer := range pod.Spec.Containers {
			containerInfo := &K8sContainerInfo{
				Name:        tmpContainer.Name,
				HostPortMap: make(map[int32]int32),
				RefPodInfo:  cachePodInfo,
			}
			// Not specifying a port DOES NOT prevent that port from being exposed.
			// So Ports could be empty, if so we only record its IP address.
			if len(tmpContainer.Ports) == 0 {
				// If there is more than one container that doesn't specify a port,
				// we would rather get an empty name than get an incorrect one.
				if len(pod.Spec.Containers) > 1 {
					containerInfo.Name = ""
				}
				// When there are many containers in one pod and only part of them have ports,
				// the containers at the back will overwrite the ones at the front here.
				MetaDataCache.AddContainerByIpPort(pod.Status.PodIP, 0, containerInfo)
				cachePodInfo.Ports = append(cachePodInfo.Ports, 0)
				continue
			}
			for _, port := range tmpContainer.Ports {
				cachePodInfo.Ports = append(cachePodInfo.Ports, port.ContainerPort)
				// If hostPort is specified, add the container using HostIP and HostPort
				if port.HostPort != 0 {
					containerInfo.HostPortMap[port.HostPort] = port.ContainerPort
					cachePodInfo.HostPorts = append(cachePodInfo.HostPorts, port.HostPort)
					MetaDataCache.AddContainerByHostIpPort(pod.Status.HostIP, uint32(port.HostPort), containerInfo)
				}
				MetaDataCache.AddContainerByIpPort(pod.Status.PodIP, uint32(port.ContainerPort), containerInfo)
			}
		}
	}
	GlobalPodInfo.add(cachePodInfo)
}

func getControllerKindName(pod *corev1.Pod) (workloadKind string, workloadName string) {
	for _, owner := range pod.OwnerReferences {
		// only care about the controller
		if owner.Controller == nil || *owner.Controller != true {
			continue
		}
		if owner.Kind == ReplicaSetKind {
			// The owner of Pod is ReplicaSet, and it is Workload such as Deployment for ReplicaSet.
			// Therefore, find ReplicaSet's name in 'globalRsInfo' to find which kind of workload
			// the Pod belongs to.
			if workload, ok := GlobalRsInfo.GetOwnerReference(mapKey(pod.Namespace, owner.Name)); ok {
				workloadKind = CompleteGVK(workload.APIVersion, strings.ToLower(workload.Kind))
				workloadName = workload.Name
				return
			}
		}
		// If the owner of pod is not ReplicaSet or the replicaset has no controller
		workloadKind = CompleteGVK(owner.APIVersion, strings.ToLower(owner.Kind))
		workloadName = owner.Name
		return
	}
	return
}

func PodUpdate(objOld interface{}, objNew interface{}) {
	oldPod := objOld.(*corev1.Pod)
	newPod := objNew.(*corev1.Pod)
	if oldPod.ResourceVersion == newPod.ResourceVersion {
		// Periodic resync will send update events for all known pods.
		// Two different versions of the same pod will always have different RVs.
		return
	}

	oldCachePod, ok := GlobalPodInfo.get(oldPod.Namespace, oldPod.Name)
	if !ok {
		PodAdd(objNew)
		return
	}
	// Always override the old pod in the cache
	PodAdd(objNew)

	// Delay delete the pod using the difference between the old pod and the new one
	deletedPodInfo := &deletedPodInfo{
		uid:          string(oldPod.UID),
		name:         "",
		namespace:    oldPod.Namespace,
		containerIds: nil,
		ip:           oldPod.Status.PodIP,
		ports:        nil,
		hostIp:       oldPod.Status.HostIP,
		hostPorts:    nil,
	}

	if oldPod.Name != newPod.Name {
		deletedPodInfo.name = oldPod.Name
	}

	// Check the containers' ID
	newContainerIds := make([]string, 0)
	for _, containerStatus := range newPod.Status.ContainerStatuses {
		shortenContainerId := TruncateContainerId(containerStatus.ContainerID)
		if shortenContainerId == "" {
			continue
		}
		newContainerIds = append(newContainerIds, shortenContainerId)
	}
	containerIdCompare := compare.NewStringSlice(oldCachePod.ContainerIds, newContainerIds)
	containerIdCompare.Compare()
	deletedPodInfo.containerIds = containerIdCompare.GetRemovedElements()
	if dsfEnable {
		for _, deletedContainerIds := range deletedPodInfo.containerIds {
			MetaDataCache.DeleteLocalDSFRuleByContainerId(deletedContainerIds)
		}
	}

	// Check the ports specified.
	newPorts := make([]int32, 0)
	newHostPorts := make([]int32, 0)
	for _, container := range newPod.Spec.Containers {
		if len(container.Ports) == 0 {
			newPorts = append(newPorts, 0)
			continue
		}
		for _, port := range container.Ports {
			newPorts = append(newPorts, port.ContainerPort)
			// If hostPort is specified, add the container using HostIP and HostPort
			if port.HostPort != 0 {
				newHostPorts = append(newHostPorts, port.HostPort)
			}
		}
	}

	if oldPod.Status.PodIP != newPod.Status.PodIP {
		deletedPodInfo.ports = oldCachePod.Ports
	} else {
		portsCompare := compare.NewInt32Slice(oldCachePod.Ports, newPorts)
		portsCompare.Compare()
		deletedPodInfo.ports = portsCompare.GetRemovedElements()
	}

	if oldPod.Status.HostIP != newPod.Status.HostIP {
		deletedPodInfo.hostPorts = oldCachePod.HostPorts
	} else {
		hostPortsCompare := compare.NewInt32Slice(oldCachePod.HostPorts, newHostPorts)
		hostPortsCompare.Compare()
		deletedPodInfo.hostPorts = hostPortsCompare.GetRemovedElements()
	}

	// Wait for a few seconds to remove the cache data
	podDeleteQueueMut.Lock()
	podDeleteQueue = append(podDeleteQueue, deleteRequest{
		podInfo: deletedPodInfo,
		ts:      time.Now(),
	})
	podDeleteQueueMut.Unlock()
}

func PodDelete(obj interface{}) {
	pod := obj.(*corev1.Pod)
	podInfo := &deletedPodInfo{
		uid:          string(pod.UID),
		name:         pod.Name,
		namespace:    pod.Namespace,
		containerIds: make([]string, 0),
		ip:           pod.Status.PodIP,
		ports:        make([]int32, 0),
		hostIp:       pod.Status.HostIP,
		hostPorts:    make([]int32, 0),
	}

	for _, containerStatus := range pod.Status.ContainerStatuses {
		shortenContainerId := TruncateContainerId(containerStatus.ContainerID)
		if shortenContainerId == "" {
			continue
		}
		podInfo.containerIds = append(podInfo.containerIds, shortenContainerId)
	}
	for _, deletedContainerIds := range podInfo.containerIds {
		MetaDataCache.DeleteLocalDSFRuleByContainerId(deletedContainerIds)
	}

	for _, container := range pod.Spec.Containers {
		if len(container.Ports) == 0 {
			podInfo.ports = append(podInfo.ports, 0)
			continue
		}
		for _, port := range container.Ports {
			podInfo.ports = append(podInfo.ports, port.ContainerPort)
			// If hostPort is specified, add the container using HostIP and HostPort
			if port.HostPort != 0 {
				podInfo.hostPorts = append(podInfo.hostPorts, port.HostPort)
			}
		}
	}

	if enableGraceDeletePeriod {
		// Wait for a few seconds to remove the cache data
		podDeleteQueueMut.Lock()
		podDeleteQueue = append(podDeleteQueue, deleteRequest{
			podInfo: podInfo,
			ts:      time.Now(),
		})
		podDeleteQueueMut.Unlock()
	} else {
		deletePodInfo(podInfo)
	}
}

// TruncateContainerId slices the input containerId into two parts separated by "://",
// and return the first 12 bytes at most of the second part.
//
// If no second part found, return empty string.
func TruncateContainerId(containerId string) string {
	sep := "://"
	separated := strings.SplitN(containerId, sep, 2)
	if len(separated) < 2 {
		return ""
	}
	secondString := separated[1]
	l := len(secondString)
	if l > 12 {
		l = 12
	}
	return secondString[0:l]
}

func TruncateComplateContainerId(containerId string) string {
	sep := "://"
	separated := strings.SplitN(containerId, sep, 2)
	if len(separated) < 2 {
		return ""
	}
	return separated[1]
}

func getHostIpFromEnv() string {
	value, ok := os.LookupEnv("MY_NODE_IP")
	if !ok {
		// return "unknow"
		return "unknow"
	}
	return value
}
