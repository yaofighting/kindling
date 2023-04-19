package detect

import (
	"time"

	"github.com/Kindling-project/kindling/collector/pkg/extension/detect/dialprotocol"
	probing "github.com/prometheus-community/pro-bing"
)

// AvailabilityDetect is a package to help used to check network healthy by doing specifect Network calling, such as  ICMP / IP / TCP calling
type AvailabilityDetect interface {
	SubmitTask(task DialTask, timeout time.Duration, callBack reports)
	SearchResult(reportCode string, batchCode string) (status *ExecutorStatus)
	ShutdownTask(reportCode string, batchCode string) (status *ExecutorStatus)
}

type reports func(*ExecutorStatus)

type DetectResult struct {
	// Link to SubTask
	// subTask *SubTask
	Type                   TaskType     `json:"type"`                       // the type of this Detect
	Labels                 DetectLabels `json:"labels"`                     // this labels of this Detect
	DetectReportCode       int64        `json:"detect_report_code"`         // the code of Report
	DetectResult           bool         `json:"detect_result"`              // whether this Detect is success
	DetectResultDetailCode int64        `json:"detect_request_detail_code"` // the code of detail message of this detect
	TimeSpend              int64        `json:"time_spend"`                 // how many (nanoSeconds?) did this detect cost
	TotalRequest           int          `json:"total_request"`              // the count of Detect for this Report
}

type Result interface {
	GetTaskInfo() Task
}

type NetworkAvailabilityDetectResult struct {
	DetectResult
	probing.Statistics
}

// TODO Can not use these in agents
type DetectLabels struct {
	RegionCode     string `json:"region_code"`
	DataCenterCode string `json:"datecenter_code"`
	ClusterCode    string `json:"cluster_code"`
	NamespaceCode  string `json:"namespace_code"`
}

type AvailabilityDetectReport struct {
	DetectRequestDetailCode string `json:"detect_request_detail_code"`

	*TargetNodeInfo   `json:",omitempty"`
	*TargetServicenfo `json:",omitempty"`

	Protocol     dialprotocol.Protocol `json:"protocol"`
	DetectResult bool                  `json:"detect_result"`

	TimeSpent    int64 `json:"time_spent_millsecond"`
	StartTime    int64 `json:"timestamp"`
	FinishedTime int64 `json:"finished_time"`

	*NetDetectResultDetail     `json:"net_result_detail,omitempty"`
	*ServiceDetectResultDetail `json:"svc_result_detail,omitempty"`

	*Task
	*AgentInfo
}

type AgentInfo struct {
	MasterIp string `json:"masterIp"`
	NodeIp   string `json:"node_ip"`
	Instance string `json:"instance"`
}

type TargetNodeInfo struct {
	TargetNodeName string `json:"target_node_name"`
	TargetNodeIp   string `json:"target_node_ip"`
}

type TargetServicenfo struct {
	TargetServiceName string `json:"target_service_name"`
	TargetServiceIp   string `json:"target_service_ip"`
}

type NetDetectResultDetail struct {
	Send       int   `json:"send"`
	Receive    int   `json:"receive"`
	PacketLoss int   `json:"packet_loss"`
	AvgRtt     int64 `json:"avg_rtt_micosecond"`
	MaxRtt     int64 `json:"max_rtt_micosecond"`
	MinRtt     int64 `json:"min_rtt_micosecond"`
}

type ServiceDetectResultDetail struct {
	Send    int `json:"send"`
	Receive int `json:"receive"`
}
