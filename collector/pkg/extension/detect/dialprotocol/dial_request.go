package dialprotocol

import "time"

type Protocol int

const (
	ICMP Protocol = iota
	TCP
	HTTP
	HTTPS
)

type DialRequest struct {
	SubTaskId string                 // 子任务ID，用于关联一次任务实际的请求
	Host      string                 // 指定的目的地地址,可以是域名/IP; 理论上不应包含端口
	Protocol  Protocol               // 使用的协议类型
	Count     int                    // 次数
	Interval  time.Duration          // 间隔时间
	Arguments map[string]interface{} // 对不同的协议配置单独的参数；比如 port;url;param;header;frequencry
}
