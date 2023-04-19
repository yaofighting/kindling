package detect

import "time"

type TaskType int

type DestinationType int

const (
	NetworkAvailabilityTask TaskType = 0
	ServiceAvailabilityTask TaskType = 1
	ConflictDetectTask      TaskType = 2
)

const (
	AllNodeInCluster DestinationType = 0
	TargetNode       DestinationType = 1
)

type Task struct {
	TaskId     int64         `json:"task_id"`
	TaskName   string        `json:"task_name"`
	TaskType   TaskType      `json:"task_type"`
	ReportCode string        `json:"detect_report_code"`
	BatchCode  string        `json:"batchCode"`
	Timeout    time.Duration `json:"-"` //总超时时间
}

type TaskVO struct {
	TaskId          int64  `json:"taskId"`          // 任务Id/纯数字
	TaskName        string `json:"taskName"`        // 任务名称
	ReportCode      string `json:"reportCode"`      // 报告号 使用报告号+批次号来唯一确定一次执行
	BatchCode       string `json:"batchCode"`       // 批次号 可以为空
	TaskType        int    `json:"taskType"`        // 探测类型: 0-网络可用性 1-服务可用性 2-资源冲突 TODO 资源冲突暂时未支持
	DestinationType int    `json:"destinationType"` // 目的地址的种类： 0-探针所在集群所有节点，1-指定的地址
	ServiceAddress  string `json:"serviceAddress"`  // 目标服务地址, e.g. http://xxxxx
	Protocol        int    `json:"protocol"`        // 协议: 0: TCP 1 HTTP 2 HTTPS 3 ICMP
	RequestParams   string `json:"requestParams"`   // 请求参数 : 仅服务可用性测试会包含 e.g. ?zxczxc=123123
	RequestMethod   string `json:"requestMethod"`   // 请求方式: 请求方式/GEI/POST
	ConflictType    int    `json:"conflictType"`    // 冲突类型:0. IP冲突 1. 路由冲突  仅资源冲突检测包含
}
