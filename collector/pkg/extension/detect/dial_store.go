package detect

import (
	"sync"
	"time"
)

type DialStore struct {
	Executors    map[string]Executor
	ReportStream chan<- *AvailabilityDetectReport

	rwMux sync.RWMutex
}

func (e *DialStore) SubmitTask(task DialTask, timeout time.Duration, callBack reports) {
	e.rwMux.Lock()
	defer e.rwMux.Unlock()

	// TODO taskId+批次号
	if _, ok := e.Executors[task.GetUnqiueCode()]; ok {
		// 任务在记录中已经存在了
		return
	}

	// e.checkTask(task)
	exec := e.DialExecutor(task)

	go exec.Start(timeout, func(es *ExecutorStatus) {
		//  任务结束时，从map中移除自己的记录,并执行整体任务报告回显
		e.rwMux.Lock()
		e.Executors[task.GetUnqiueCode()] = nil
		e.rwMux.Unlock()
		callBack(es)
	}, e.ReportStream)
}

func (e *DialStore) SearchResult(reportCode string, batchCode string) (status *ExecutorStatus) {
	e.rwMux.RLock()
	defer e.rwMux.RUnlock()
	if executor, ok := e.Executors[reportCode+batchCode]; ok {
		return executor.Status()
	} else {
		return nil
	}
}

func (e *DialStore) ShutdownTask(reportCode string, batchCode string) (status *ExecutorStatus) {
	e.rwMux.RLock()
	defer e.rwMux.RUnlock()
	if executor, ok := e.Executors[reportCode+batchCode]; ok {
		executor.Shutdown()
		return executor.Status()
	} else {
		return nil
	}
}

func (e *DialStore) DialExecutor(task DialTask) Executor {
	executor := &DialExecutor{}
	executor.SetTask(task)
	executor.Infinity = task.IsInfinity()
	e.Executors[task.GetUnqiueCode()] = executor
	return executor
}

func NewDialStore(reportCh chan<- *AvailabilityDetectReport) *DialStore {
	return &DialStore{
		Executors:    make(map[string]Executor, 20),
		ReportStream: reportCh,
	}
}
