package detect

import (
	"context"
	"sync"
	"time"

	"github.com/Kindling-project/kindling/collector/pkg/component"
	"github.com/Kindling-project/kindling/collector/pkg/extension/detect/dialprotocol"
)

type ContextKey string

type Status int

const SubTaskCount ContextKey = "subTaskCount"

const (
	RUNNING Status = iota
	FINISHED
	CANCELED
)

type Executor interface {
	SetTask(DialTask) bool
	SetSubTaskTimeout(timeOut time.Duration)
	Start(timeOut time.Duration, callback reports, reportStream chan<- *AvailabilityDetectReport)
	Status() *ExecutorStatus
	Shutdown()
}

type ExecutorStatus struct {
	Status

	subTasks []dialprotocol.DialRequest
	results  map[string]*AvailabilityDetectReport

	rwMux sync.RWMutex
}

func (es *ExecutorStatus) SetSubTask(subTasks []dialprotocol.DialRequest) {
	es.subTasks = subTasks
	es.results = make(map[string]*AvailabilityDetectReport, len(subTasks))
}

func (es *ExecutorStatus) GetSubTask() (subTasks []dialprotocol.DialRequest) {
	return es.subTasks
}

func (es *ExecutorStatus) UpdateResult(subTaskId string, result *AvailabilityDetectReport) {
	es.rwMux.Lock()
	defer es.rwMux.Unlock()
	es.results[subTaskId] = result
}

// GetResultMap read-only!!!
func (es *ExecutorStatus) GetResultMap() map[string]*AvailabilityDetectReport {
	es.rwMux.RLock()
	defer es.rwMux.RUnlock()

	targetResult := make(map[string]*AvailabilityDetectReport, len(es.results))
	for subTaskId, result := range es.results {
		targetResult[subTaskId] = result
	}
	return targetResult
}

type DialExecutor struct {
	DialTask
	SubTaskTimeout time.Duration
	Ctx            context.Context

	cancel context.CancelFunc

	ExecStatus  ExecutorStatus
	ResultRWMux sync.RWMutex

	Infinity bool

	logger component.TelemetryLogger
}

func (de *DialExecutor) SetTask(task DialTask) bool {
	de.DialTask = task
	de.Ctx, de.cancel = context.WithCancel(context.Background())
	de.SubTaskTimeout = 0

	subTasks := task.GetDialRequest()
	de.ExecStatus.SetSubTask(subTasks)

	de.Ctx = context.WithValue(de.Ctx, SubTaskCount, len(subTasks))
	return true
}

func (de *DialExecutor) SetSubTaskTimeout(timeOut time.Duration) {
	de.SubTaskTimeout = timeOut
}

func (de *DialExecutor) Start(timeout time.Duration, callback reports, report chan<- *AvailabilityDetectReport) {
	var taskCtx context.Context
	var cancel context.CancelFunc

	taskCtx, cancel = context.WithTimeout(de.Ctx, timeout)
	defer cancel()

	// TODO Debug option
	// For every packet record
	// resultStream := make(chan *AvailabilityDetectReport, 10)
	var wg sync.WaitGroup
	subTasks := de.GetDialRequest()
	de.ExecStatus.Status = RUNNING
	wg.Add(len(subTasks))
	for i := 0; i < len(subTasks); i++ {
		subTask := subTasks[i]
		go func() {
			defer wg.Done()
			result := de.execute(taskCtx, subTask)
			result.Task = de.GetTask()
			de.ExecStatus.UpdateResult(result.DetectRequestDetailCode, result)
			report <- result
		}()
	}

	wg.Wait()

	// TODO Record every packet
	//result_count := 0
	// for {
	// 	select {
	// 	case <-taskCtx.Done():
	// 		de.ExecStatus.Status = CANCELED
	// 		wg.Wait()
	// 	DONE:
	// 		for {
	// 			select {
	// 			case result := <-resultStream:
	// 				de.ExecStatus.UpdateResult(result.DetectRequestDetailCode, result)
	// 				result_count++
	// 			default:
	// 				break DONE
	// 			}
	// 		}
	// 		if result_count == len(subTasks) {
	// 			de.ExecStatus.Status = FINISHED
	// 		}
	// 		callback(&de.ExecStatus)
	// 		return
	// 	case result := <-resultStream:
	// 		de.ExecStatus.UpdateResult(result.DetectRequestDetailCode, result)
	// 		result_count++
	// 		if result_count == len(subTasks) {
	// 			de.ExecStatus.Status = FINISHED
	// 			callback(&de.ExecStatus)
	// 			return
	// 		}
	// 	}
	// }
}

func (de *DialExecutor) Status() *ExecutorStatus {
	return &de.ExecStatus
}

func (de *DialExecutor) Shutdown() {
	de.cancel()
}

func (de *DialExecutor) execute(ctx context.Context, dialRequest dialprotocol.DialRequest) *AvailabilityDetectReport {
	startTime := time.Now()
	result := &AvailabilityDetectReport{
		DetectRequestDetailCode: dialRequest.SubTaskId,
		Protocol:                dialRequest.Protocol,
		StartTime:               startTime.Unix(),
		AgentInfo:               &agentInfo,
	}
	switch dialRequest.Protocol {
	case dialprotocol.ICMP:
		pingStatus, err := dialprotocol.ExecuteICMP(ctx, dialRequest, nil)
		if err != nil {
			result.DetectResult = false
		} else {
			result.DetectResult = true
			result.NetDetectResultDetail = &NetDetectResultDetail{
				Send:       pingStatus.PacketsSent,
				Receive:    pingStatus.PacketsRecv,
				PacketLoss: pingStatus.PacketsSent - pingStatus.PacketsRecv,
				AvgRtt:     pingStatus.AvgRtt.Microseconds(),
				MaxRtt:     pingStatus.MaxRtt.Microseconds(),
				MinRtt:     pingStatus.MinRtt.Microseconds(),
			}
			targetNodeName := dialRequest.Host
			targetNodeIp := pingStatus.IPAddr.String()
			if targetNodeIp == targetNodeName {
				// Only Set targetNodeIp
				result.TargetNodeInfo = &TargetNodeInfo{
					TargetNodeIp: targetNodeIp,
				}
			} else {
				result.TargetNodeInfo = &TargetNodeInfo{
					TargetNodeIp:   targetNodeIp,
					TargetNodeName: targetNodeName,
				}
			}
		}
	case dialprotocol.HTTP, dialprotocol.HTTPS:
		// TODO dialProtocol

	case dialprotocol.TCP:
		err := dialprotocol.ExecuteTCP(ctx, dialRequest.Host)
		if err != nil {
			result.DetectResult = false
		} else {
			result.DetectResult = true
		}
	}
	finishedTime := time.Now()
	result.TimeSpent = finishedTime.Sub(startTime).Milliseconds()
	result.FinishedTime = finishedTime.UnixMilli()
	return result
}
