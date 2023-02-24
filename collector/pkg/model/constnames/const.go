package constnames

const (
	ReadEvent     = "read"
	WriteEvent    = "write"
	ReadvEvent    = "readv"
	WritevEvent   = "writev"
	SendToEvent   = "sendto"
	RecvFromEvent = "recvfrom"
	SendMsgEvent  = "sendmsg"
	RecvMsgEvent  = "recvmsg"
	ConnectEvent  = "connect"

	TcpHandshakeEvent    = "tcp_handshake_rtt"
	TcpPacketCountsEvent = "tcp_packet_counts"
	TcpAckDelayEvent     = "tcp_average_ack_delay"

	TcpCloseEvent          = "tcp_close"
	TcpRcvEstablishedEvent = "tcp_rcv_established"
	TcpDropEvent           = "tcp_drop"
	TcpRetransmitSkbEvent  = "tcp_retransmit_skb"
	TcpConnectEvent        = "tcp_connect"
	TcpSetStateEvent       = "tcp_set_state"

	CpuEvent           = "cpu_event"
	JavaFutexInfo      = "java_futex_info"
	TransactionIdEvent = "apm_trace_id_event"
	SpanEvent          = "apm_span_event"
	OtherEvent         = "other"

	ProcessExitEvent = "procexit"
	GrpcUprobeEvent  = "grpc_uprobe"
	// NetRequestMetricGroupName is used for dataGroup generated from networkAnalyzer.
	NetRequestMetricGroupName = "net_request_metric_group"
	// SingleNetRequestMetricGroup stands for the dataGroup with abnormal status.
	SingleNetRequestMetricGroup = "single_net_request_metric_group"
	// AggregatedNetRequestMetricGroup stands for the dataGroup after aggregation.
	AggregatedNetRequestMetricGroup = "aggregated_net_request_metric_group"

	CameraEventGroupName = "camera_event_group"

	TcpRttMetricGroupName        = "tcp_rtt_metric_group"
	TcpRetransmitMetricGroupName = "tcp_retransmit_metric_group"
	TcpDropMetricGroupName       = "tcp_drop_metric_group"
	NodeMetricGroupName          = "node_metric_metric_group"
	TcpConnectMetricGroupName    = "tcp_connect_metric_group"
	TcpHandshakeRttGroupName     = "tcp_handshake_rtt_metric_group"
	TcpPacketCountsGroupName     = "tcp_packet_counts_metric_group"
	TcpAckDelayGroupName         = "tcp_average_ack_delay_metric_group"
)
