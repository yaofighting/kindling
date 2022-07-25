package model

import "encoding/json"

type Source int32

const (
	Source_SOURCE_UNKNOWN Source = 0
	Source_SYSCALL_ENTER  Source = 1
	Source_SYSCALL_EXIT   Source = 2
	Source_TRACEPOINT     Source = 3
	Source_KRPOBE         Source = 4
	Source_KRETPROBE      Source = 5
	Source_UPROBE         Source = 6
	Source_URETPROBE      Source = 7
)

var Source_name = map[int32]string{
	0: "SOURCE_UNKNOWN",
	1: "SYSCALL_ENTER",
	2: "SYSCALL_EXIT",
	3: "TRACEPOINT",
	4: "KRPOBE",
	5: "KRETPROBE",
	6: "UPROBE",
	7: "URETPROBE",
}

var Source_value = map[string]int32{
	"SOURCE_UNKNOWN": 0,
	"SYSCALL_ENTER":  1,
	"SYSCALL_EXIT":   2,
	"TRACEPOINT":     3,
	"KRPOBE":         4,
	"KRETPROBE":      5,
	"UPROBE":         6,
	"URETPROBE":      7,
}

func (x Source) String() string {
	return "SOURCE_UNKNOWN"
}

type Category int32

const (
	Category_CAT_NONE      Category = 0
	Category_CAT_OTHER     Category = 1
	Category_CAT_FILE      Category = 2
	Category_CAT_NET       Category = 3
	Category_CAT_IPC       Category = 4
	Category_CAT_WAIT      Category = 5
	Category_CAT_SIGNAL    Category = 6
	Category_CAT_SLEEP     Category = 7
	Category_CAT_TIME      Category = 8
	Category_CAT_PROCESS   Category = 9
	Category_CAT_SCHEDULER Category = 10
	Category_CAT_MEMORY    Category = 11
	Category_CAT_USER      Category = 12
	Category_CAT_SYSTEM    Category = 13
)

var Category_name = map[int32]string{
	0:  "CAT_NONE",
	1:  "CAT_OTHER",
	2:  "CAT_FILE",
	3:  "CAT_NET",
	4:  "CAT_IPC",
	5:  "CAT_WAIT",
	6:  "CAT_SIGNAL",
	7:  "CAT_SLEEP",
	8:  "CAT_TIME",
	9:  "CAT_PROCESS",
	10: "CAT_SCHEDULER",
	11: "CAT_MEMORY",
	12: "CAT_USER",
	13: "CAT_SYSTEM",
}

var Category_value = map[string]int32{
	"CAT_NONE":      0,
	"CAT_OTHER":     1,
	"CAT_FILE":      2,
	"CAT_NET":       3,
	"CAT_IPC":       4,
	"CAT_WAIT":      5,
	"CAT_SIGNAL":    6,
	"CAT_SLEEP":     7,
	"CAT_TIME":      8,
	"CAT_PROCESS":   9,
	"CAT_SCHEDULER": 10,
	"CAT_MEMORY":    11,
	"CAT_USER":      12,
	"CAT_SYSTEM":    13,
}

type ValueType int32

const (
	ValueType_NONE    ValueType = 0
	ValueType_INT8    ValueType = 1
	ValueType_INT16   ValueType = 2
	ValueType_INT32   ValueType = 3
	ValueType_INT64   ValueType = 4
	ValueType_UINT8   ValueType = 5
	ValueType_UINT16  ValueType = 6
	ValueType_UINT32  ValueType = 7
	ValueType_UINT64  ValueType = 8
	ValueType_CHARBUF ValueType = 9
	ValueType_BYTEBUF ValueType = 10
	ValueType_FLOAT   ValueType = 11
	ValueType_DOUBLE  ValueType = 12
	ValueType_BOOL    ValueType = 13
)

var ValueType_name = map[int32]string{
	0:  "NONE",
	1:  "INT8",
	2:  "INT16",
	3:  "INT32",
	4:  "INT64",
	5:  "UINT8",
	6:  "UINT16",
	7:  "UINT32",
	8:  "UINT64",
	9:  "CHARBUF",
	10: "BYTEBUF",
	11: "FLOAT",
	12: "DOUBLE",
	13: "BOOL",
}

var ValueType_value = map[string]int32{
	"NONE":    0,
	"INT8":    1,
	"INT16":   2,
	"INT32":   3,
	"INT64":   4,
	"UINT8":   5,
	"UINT16":  6,
	"UINT32":  7,
	"UINT64":  8,
	"CHARBUF": 9,
	"BYTEBUF": 10,
	"FLOAT":   11,
	"DOUBLE":  12,
	"BOOL":    13,
}

// File Descriptor type
type FDType int32

const (
	FDType_FD_UNKNOWN       FDType = 0
	FDType_FD_FILE          FDType = 1
	FDType_FD_DIRECTORY     FDType = 2
	FDType_FD_IPV4_SOCK     FDType = 3
	FDType_FD_IPV6_SOCK     FDType = 4
	FDType_FD_IPV4_SERVSOCK FDType = 5
	FDType_FD_IPV6_SERVSOCK FDType = 6
	FDType_FD_FIFO          FDType = 7
	FDType_FD_UNIX_SOCK     FDType = 8
	FDType_FD_EVENT         FDType = 9
	FDType_FD_UNSUPPORTED   FDType = 10
	FDType_FD_SIGNALFD      FDType = 11
	FDType_FD_EVENTPOLL     FDType = 12
	FDType_FD_INOTIFY       FDType = 13
	FDType_FD_TIMERFD       FDType = 14
	FDType_FD_NETLINK       FDType = 15
	FDType_FD_FILE_V2       FDType = 16
)

var FDType_name = map[int32]string{
	0:  "FD_UNKNOWN",
	1:  "FD_FILE",
	2:  "FD_DIRECTORY",
	3:  "FD_IPV4_SOCK",
	4:  "FD_IPV6_SOCK",
	5:  "FD_IPV4_SERVSOCK",
	6:  "FD_IPV6_SERVSOCK",
	7:  "FD_FIFO",
	8:  "FD_UNIX_SOCK",
	9:  "FD_EVENT",
	10: "FD_UNSUPPORTED",
	11: "FD_SIGNALFD",
	12: "FD_EVENTPOLL",
	13: "FD_INOTIFY",
	14: "FD_TIMERFD",
	15: "FD_NETLINK",
	16: "FD_FILE_V2",
}

var FDType_value = map[string]int32{
	"FD_UNKNOWN":       0,
	"FD_FILE":          1,
	"FD_DIRECTORY":     2,
	"FD_IPV4_SOCK":     3,
	"FD_IPV6_SOCK":     4,
	"FD_IPV4_SERVSOCK": 5,
	"FD_IPV6_SERVSOCK": 6,
	"FD_FIFO":          7,
	"FD_UNIX_SOCK":     8,
	"FD_EVENT":         9,
	"FD_UNSUPPORTED":   10,
	"FD_SIGNALFD":      11,
	"FD_EVENTPOLL":     12,
	"FD_INOTIFY":       13,
	"FD_TIMERFD":       14,
	"FD_NETLINK":       15,
	"FD_FILE_V2":       16,
}

type L4Proto int32

const (
	L4Proto_UNKNOWN L4Proto = 0
	L4Proto_TCP     L4Proto = 1
	L4Proto_UDP     L4Proto = 2
	L4Proto_ICMP    L4Proto = 3
	L4Proto_RAW     L4Proto = 4
)

var L4Proto_name = map[int32]string{
	0: "UNKNOWN",
	1: "TCP",
	2: "UDP",
	3: "ICMP",
	4: "RAW",
}

var L4Proto_value = map[string]int32{
	"UNKNOWN": 0,
	"TCP":     1,
	"UDP":     2,
	"ICMP":    3,
	"RAW":     4,
}

func (m *KindlingEvent) String() string {
	data, _ := json.Marshal(&m)
	return string(data)
}

type KindlingEvent struct {
	Source Source
	// Timestamp in nanoseconds at which the event were collected.
	Timestamp uint64
	// Name of Kindling Event
	Name string
	// Category of Kindling Event, enum
	Category Category
	// Number of UserAttributes
	ParamsNumber uint16
	// Slow Syscall flag
	SlowSyscall bool
	// User-defined Attributions of Kindling Event, now including latency for syscall.
	UserAttributes [8]KeyValue
	// Context includes Thread information and Fd information.
	Ctx Context
}

func (k *KindlingEvent) Reset() {
	k.Ctx.FdInfo.Num = 0
	k.Ctx.ThreadInfo.Pid = 0
}

func (m *KindlingEvent) GetSource() Source {
	if m != nil {
		return m.Source
	}
	return Source_SOURCE_UNKNOWN
}

func (m *KindlingEvent) GetTimestamp() uint64 {
	if m != nil {
		return m.Timestamp
	}
	return 0
}

func (m *KindlingEvent) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *KindlingEvent) GetCategory() Category {
	if m != nil {
		return m.Category
	}
	return Category_CAT_NONE
}

func (m *KindlingEvent) GetUserAttributes() *[8]KeyValue {
	return &m.UserAttributes
}

func (m *KindlingEvent) GetCtx() *Context {
	return &m.Ctx
}

type KeyValue struct {
	// Arguments' Name or Attributions' Name.
	Key string
	// Type of Value.
	ValueType ValueType
	// Value of Key in bytes, should be converted according to ValueType.
	Value []byte
}

func (m *KeyValue) GetKey() string {
	if m != nil {
		return m.Key
	}
	return ""
}

func (m *KeyValue) GetValueType() ValueType {
	if m != nil {
		return m.ValueType
	}
	return ValueType_NONE
}

func (m *KeyValue) GetValue() []byte {
	if m != nil {
		return m.Value
	}
	return nil
}

type Context struct {
	// Thread information corresponding to Kindling Event, optional.
	ThreadInfo Thread
	// Fd information corresponding to Kindling Event, optional.
	FdInfo Fd
}

func (m *Context) GetThreadInfo() *Thread {
	return &m.ThreadInfo
}

func (m *Context) GetFdInfo() *Fd {
	return &m.FdInfo
}

type Thread struct {
	// Process id of thread.
	Pid uint32
	// Thread/task id of thread.
	Tid uint32
	// User id of thread
	Uid uint32
	// Group id of thread
	Gid uint32
	// Command of thread.
	Comm string
	// ContainerId of thread
	ContainerId string
	// ContainerName of thread
	ContainerName string
}

func (m *Thread) GetPid() uint32 {
	if m != nil {
		return m.Pid
	}
	return 0
}

func (m *Thread) GetTid() uint32 {
	if m != nil {
		return m.Tid
	}
	return 0
}

func (m *Thread) GetUid() uint32 {
	if m != nil {
		return m.Uid
	}
	return 0
}

func (m *Thread) GetGid() uint32 {
	if m != nil {
		return m.Gid
	}
	return 0
}

func (m *Thread) GetComm() string {
	if m != nil {
		return m.Comm
	}
	return ""
}

func (m *Thread) GetContainerId() string {
	if m != nil {
		return m.ContainerId
	}
	return ""
}

func (m *Thread) GetContainerName() string {
	if m != nil {
		return m.ContainerName
	}
	return ""
}

type Fd struct {
	// FD number.
	Num int32
	// Type of FD in enum.
	TypeFd FDType
	// if FD is type of file
	Filename  string
	Directory string
	// if FD is type of ipv4 or ipv6
	Protocol L4Proto
	// repeated for ipv6, client_ip[0] for ipv4
	Role  bool
	Sip   []uint32
	Dip   []uint32
	Sport uint32
	Dport uint32
	// if FD is type of unix_sock
	// Source socket endpoint
	Source uint64
	// Destination socket endpoint
	Destination uint64
}

func (m *Fd) GetNum() int32 {
	if m != nil {
		return m.Num
	}
	return 0
}

func (m *Fd) GetTypeFd() FDType {
	if m != nil {
		return m.TypeFd
	}
	return FDType_FD_UNKNOWN
}

func (m *Fd) GetFilename() string {
	if m != nil {
		return m.Filename
	}
	return ""
}

func (m *Fd) GetDirectory() string {
	if m != nil {
		return m.Directory
	}
	return ""
}

func (m *Fd) GetProtocol() L4Proto {
	if m != nil {
		return m.Protocol
	}
	return L4Proto_UNKNOWN
}

func (m *Fd) GetRole() bool {
	if m != nil {
		return m.Role
	}
	return false
}

func (m *Fd) GetSip() []uint32 {
	if m != nil {
		return m.Sip
	}
	return nil
}

func (m *Fd) GetDip() []uint32 {
	if m != nil {
		return m.Dip
	}
	return nil
}

func (m *Fd) GetSport() uint32 {
	if m != nil {
		return m.Sport
	}
	return 0
}

func (m *Fd) GetDport() uint32 {
	if m != nil {
		return m.Dport
	}
	return 0
}

func (m *Fd) GetSource() uint64 {
	if m != nil {
		return m.Source
	}
	return 0
}

func (m *Fd) GetDestination() uint64 {
	if m != nil {
		return m.Destination
	}
	return 0
}
