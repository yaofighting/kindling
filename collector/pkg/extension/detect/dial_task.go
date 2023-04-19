package detect

import (
	"strconv"
	"time"

	"github.com/Kindling-project/kindling/collector/pkg/extension/detect/dialprotocol"
	"github.com/Kindling-project/kindling/collector/pkg/metadata/kubernetes"
)

type DialTask interface {
	GetTask() *Task
	GetUnqiueCode() string
	GetDialRequest() []dialprotocol.DialRequest
	IsInfinity() bool
}

type ServiceAvailability struct {
	Task
	TargetService    []Service
	SourceNamespaces []string
}

type NetworkAvailability struct {
	Task
	DestinationType DestinationType
	// Do not need now
	IncludeNodes []string
	// ExcludeNodes []string
}

type Service struct {
	Protocol dialprotocol.Protocol
	Endpoint string
}

func newNetAvailabilityTask(vo TaskVO) DialTask {
	task := Task{
		TaskId:     vo.TaskId,
		TaskName:   vo.TaskName,
		ReportCode: vo.ReportCode,
		BatchCode:  vo.BatchCode,
		TaskType:   NetworkAvailabilityTask,
		Timeout:    70 * time.Second,
	}

	return &NetworkAvailability{
		Task:            task,
		DestinationType: DestinationType(vo.DestinationType),
		IncludeNodes:    []string{vo.ServiceAddress},
	}
}

func GetNetDial(count int64) DialTask {
	return &NetworkAvailability{
		Task: Task{
			TaskId:     -1,
			TaskName:   "debug",
			ReportCode: time.Now().Format("2006-01-02 15:04:05"),
			BatchCode:  strconv.FormatInt(count, 10),
			TaskType:   NetworkAvailabilityTask,
			Timeout:    70 * time.Second,
		},
		DestinationType: DestinationType(0),
		IncludeNodes:    nil,
	}
}

func (na *NetworkAvailability) GetTask() *Task {
	return &na.Task
}

func (na *NetworkAvailability) GetUnqiueCode() string {
	return na.ReportCode + na.BatchCode
}

func (na *NetworkAvailability) GetDialRequest() (dials []dialprotocol.DialRequest) {
	var targetNodes []string
	arguments := map[string]interface{}{}
	if na.DestinationType == AllNodeInCluster {
		// TODO 获取当前集群内的剩余节点
		targetNodes = kubernetes.GlobalNodeInfo.GetAllNodeAddresses()
	} else if na.DestinationType == TargetNode {
		targetNodes = na.IncludeNodes
	} else {
		return nil
	}

	dials = make([]dialprotocol.DialRequest, len(targetNodes), 0)
	for _, node := range targetNodes {
		dials = append(dials, dialprotocol.DialRequest{
			// TODO SubTaskId
			SubTaskId: node,
			Host:      node,
			Protocol:  dialprotocol.ICMP,
			Arguments: arguments,
		})
	}

	return dials
}

func (na *NetworkAvailability) IsInfinity() bool {
	return na.DestinationType == AllNodeInCluster
}

func newServiceAvailabilityTask(vo TaskVO) DialTask {
	task := Task{
		TaskId:     vo.TaskId,
		TaskName:   vo.TaskName,
		ReportCode: vo.ReportCode,
		BatchCode:  vo.BatchCode,
		TaskType:   ServiceAvailabilityTask,
		Timeout:    60 * time.Second,
	}

	service := make([]Service, 1)
	service[0] = Service{
		Protocol: dialprotocol.Protocol(vo.Protocol),
		Endpoint: vo.ServiceAddress,
	}

	return &ServiceAvailability{
		Task:          task,
		TargetService: service,
	}
}

func (sa *ServiceAvailability) GetTask() *Task {
	return &sa.Task
}

func (sa *ServiceAvailability) GetUnqiueCode() string {
	return sa.ReportCode + sa.BatchCode
}

func (sa *ServiceAvailability) GetDialRequest() (dials []dialprotocol.DialRequest) {
	arguments := map[string]interface{}{}
	targets := sa.TargetService
	dials = make([]dialprotocol.DialRequest, len(targets), 0)
	for _, target := range targets {
		dials = append(dials, dialprotocol.DialRequest{
			// TODO SubTaskId
			SubTaskId: target.Endpoint,
			Host:      target.Endpoint,
			Protocol:  target.Protocol,
			Arguments: arguments,
		})
	}

	return dials
}

func (sa *ServiceAvailability) IsInfinity() bool {
	return false
}
