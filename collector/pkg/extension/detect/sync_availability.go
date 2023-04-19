package detect

/*
#cgo LDFLAGS: -L ./ -lkindling  -lstdc++ -ldl
#cgo CFLAGS: -I .
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include "../../component/receiver/cgoreceiver/cgo_func.h"
*/
import "C"
import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	"github.com/Kindling-project/kindling/collector/pkg/component"
	"github.com/Kindling-project/kindling/collector/pkg/env"
	"github.com/Kindling-project/kindling/collector/pkg/extension/detect/export"
	"go.uber.org/zap"
)

const configEndpoints = "/config/kindling"
const networkPackageEndpoints = "/network/package/update"

var agentInfo AgentInfo

type Detect struct {
	Config
	*DialStore
	*Batch

	tickerConfig         *time.Ticker
	tickerNetworkPackage *time.Ticker
	SyncInterval         time.Duration
	stopCh               chan struct{}
}

var client = &http.Client{
	Transport: &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).DialContext,
	},
}

type AvailabilityDetectReq struct {
	AgentInfo
}

type AvailabilityDetectTaskRespose struct {
	Code    int      `json:"code"`
	Message string   `json:"msg"`
	Data    []TaskVO `json:""`
}

var detectReq = &AvailabilityDetectReq{}

func init() {

	hostname, _ := env.GetHostNameFromEnv()
	// Check Error
	detectReq.Instance = hostname

	hostIp, _ := env.GetHostIpFromEnv()
	detectReq.NodeIp = hostIp

	// TODO MasterIp

}

type AvailabilityDetectReponse struct {
	Tasks []TaskVO `json:"tasks"`
}

type NetworkPackageUpdateResponse struct {
	nodeIp   string `json:"node_ip"`
	srcPodIp string `json:"src_pod_ip"`
	dstPodIp string `json:"dst_pod_port"`
	isOpen   bool   `json:"is_oprn"`
	duration int    `json:"duration"`
	isServer bool   `json:"is_server"`
}

func PostSync(req *AvailabilityDetectReq, endpoints string) (ap *AvailabilityDetectReponse) {
	data, _ := json.Marshal(req)
	resp, err := client.Post(endpoints, "application/json", bytes.NewBuffer(data))

	if err != nil {
		return nil
	}

	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	json.Unmarshal(body, ap)
	return
}

func PostNetworkPackageUpdate(req *AvailabilityDetectReq, endpoints string) (np *NetworkPackageUpdateResponse) {
	data, _ := json.Marshal(req)
	resp, err := client.Post(endpoints, "application/json", bytes.NewBuffer(data))

	if err != nil {
		return nil
	}

	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	json.Unmarshal(body, np)
	return
}

func ipToInt(ipStr string) (uint32, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0, fmt.Errorf("无效的IP地址: %s", ipStr)
	}
	ip = ip.To4()
	if ip == nil {
		return 0, fmt.Errorf("不支持IPv6地址: %s", ipStr)
	}
	return uint32(ip[0])<<24 + uint32(ip[1])<<16 + uint32(ip[2])<<8 + uint32(ip[3]), nil
}

func NewDetect(cfg Config, logger *component.TelemetryLogger) (detect *Detect) {
	agentInfo = AgentInfo{
		NodeIp: detectReq.NodeIp,
	}
	e, _ := export.NewHTTPExporter(&cfg.HTTPClientConfig)
	stopCh := make(chan struct{})

	batch := &Batch{
		BatchConfig: &cfg.BatchConfig,
		logger:      logger,
		newItem:     make(chan *AvailabilityDetectReport, 100),
		batch: batcher{
			Exporter: *e,
			req: &detectReportsRequest{
				Reports: make([]*AvailabilityDetectReport, 0, cfg.BatchConfig.SendBatchMaxSize),
			},
			count: 0,
		},
		shutdownC: stopCh,
		exportCtx: context.Background(),
	}

	detect = &Detect{
		Batch:        batch,
		SyncInterval: 15 * time.Second,
		stopCh:       stopCh,
		DialStore:    NewDialStore(batch.ReportStream()),
	}
	return detect
}

func GetServiceDial(reportCode string) DialTask {
	serviceDial := newServiceAvailabilityTask(TaskVO{
		TaskId:          -2,
		TaskName:        "debug-service-dial",
		ReportCode:      reportCode,
		TaskType:        1,
		DestinationType: 1,
		ServiceAddress:  "apm-date-receiver-svc:8080",
		Protocol:        1,
		RequestMethod:   "GET",
	})
	return serviceDial
}

func (d *Detect) Start() {

	d.tickerConfig = time.NewTicker(d.SyncInterval)
	d.tickerNetworkPackage = time.NewTicker(1 * time.Second)
	for {
		select {
		case <-d.stopCh:
			return
		case <-d.tickerNetworkPackage.C:
			networkResp := PostNetworkPackageUpdate(detectReq, networkPackageEndpoints)
			if networkResp.isOpen {
				now := time.Now()
				nanoseconds := now.UnixNano()
				srcIp, _ := ipToInt(networkResp.srcPodIp)
				dstIp, _ := ipToInt(networkResp.dstPodIp)
				C.updateFocusPodInfo(C.uint32_t(srcIp), C.uint32_t(dstIp), C.uint64_t(nanoseconds), C.uint64_t(uint64(networkResp.duration)+uint64(nanoseconds)), C.int(0))
			}
		case <-d.tickerConfig.C:
			resp := PostSync(detectReq, configEndpoints)
			for _, task := range resp.Tasks {
				switch task.TaskType {
				case int(NetworkAvailabilityTask):
					netDial := newNetAvailabilityTask(task)
					netDial.GetTask()
					d.SubmitTask(netDial, netDial.GetTask().Timeout, func(es *ExecutorStatus) {
						// TODO Console Log
						if d.logger.EnableDebug {
							d.logger.Debug("Detect id:", zap.Int64("taskId", task.TaskId))
							for _, subTask := range es.GetSubTask() {
								d.logger.Debug(fmt.Sprintf("%s: %+v", subTask.SubTaskId, es.results[subTask.SubTaskId]))
							}
						}
					})
				case int(ServiceAvailabilityTask):
					serviceDial := newServiceAvailabilityTask(task)
					d.SubmitTask(serviceDial, serviceDial.GetTask().Timeout, func(es *ExecutorStatus) {
						// TODO Console Log
						if d.logger.EnableDebug {
							d.logger.Debug("Detect id:", zap.Int64("taskId", task.TaskId))
							for _, subTask := range es.GetSubTask() {
								d.logger.Debug(fmt.Sprintf("%s: %+v", subTask.SubTaskId, es.results[subTask.SubTaskId]))
							}
						}
					})
				}
			}
		}
	}
}
