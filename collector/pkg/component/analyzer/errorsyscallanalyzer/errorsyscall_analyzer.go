package errorsyscallanalyzer

import (
	"fmt"
	"os"
	"strings"

	"github.com/Kindling-project/kindling/collector/pkg/component"
	"github.com/Kindling-project/kindling/collector/pkg/component/analyzer"
	"github.com/Kindling-project/kindling/collector/pkg/component/consumer"
	"github.com/Kindling-project/kindling/collector/pkg/model"
	"github.com/Kindling-project/kindling/collector/pkg/model/constlabels"
	"github.com/Kindling-project/kindling/collector/pkg/model/constnames"
	"github.com/hashicorp/go-multierror"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	ErrorSyscallTrace analyzer.Type = "errorsyscallanalyzer"
)

type ErrorSyscallAnalyzer struct {
	consumers     []consumer.Consumer
	telemetry     *component.TelemetryTools
	localNodeName string
}

var events []string

func NewErrorSyscallAnalyzer(cfg interface{}, telemetry *component.TelemetryTools, nextConsumers []consumer.Consumer) analyzer.Analyzer {
	var localNodeName string
	var err error
	if localNodeName, err = getHostNameFromEnv(); err != nil {
		telemetry.Logger.Warn("cannot get the local node name: ", zap.Error(err))
	}
	retAnalyzer := &ErrorSyscallAnalyzer{
		consumers:     nextConsumers,
		telemetry:     telemetry,
		localNodeName: localNodeName,
	}
	return retAnalyzer
}

func (a *ErrorSyscallAnalyzer) Start() error {
	return nil
}
func (a *ErrorSyscallAnalyzer) SetSubEvents(params map[string]string) {
	for _, syscallname := range params {
		strArr := strings.Split(syscallname, "-")
		if len(strArr) == 2 {
			events = append(events, strArr[1])
		}
	}
}

func (a *ErrorSyscallAnalyzer) ConsumableEvents() []string {
	events = append(events, "error-syscall")
	return events
}

// ConsumeEvent gets the event from the previous component
func (a *ErrorSyscallAnalyzer) ConsumeEvent(event *model.KindlingEvent) error {
	var dataGroup *model.DataGroup
	var err error

	dataGroup, err = a.generateErrorSyscall(event)
	if err != nil {
		if ce := a.telemetry.Logger.Check(zapcore.DebugLevel, "Event Skip, "); ce != nil {
			ce.Write(
				zap.Error(err),
			)
		}
		return nil
	}

	if dataGroup == nil {
		return nil
	}

	var retError error
	for _, nextConsumer := range a.consumers {
		err := nextConsumer.Consume(dataGroup)
		if err != nil {
			retError = multierror.Append(retError, err)
		}
	}
	return retError
}

func (a *ErrorSyscallAnalyzer) generateErrorSyscall(event *model.KindlingEvent) (*model.DataGroup, error) {
	labels, err := a.getErrorSyscallLabels(event)
	if err != nil {
		return nil, err
	}

	res := event.GetUserAttribute("res")
	if res == nil {
		return nil, fmt.Errorf("the syscall return value is null, wo don't get return value for %s", event.Name)
	}
	retval := res.GetIntValue()
	if retval >= 0 {
		return nil, nil
	}

	errorSyscallTrace := model.NewIntMetric(constnames.ErrorSlowSyscallTraceName, int64(retval))

	return model.NewDataGroup(constnames.ErrorSlowSyscallGroupName, labels, event.Timestamp, errorSyscallTrace), nil
}

func getHostNameFromEnv() (string, error) {
	value, ok := os.LookupEnv("MY_NODE_NAME")
	if !ok {
		return "unknown", fmt.Errorf("MY_NODE_NAME is not found in env variable which will be set unknown")
	}
	return value, nil
}

func (a *ErrorSyscallAnalyzer) getErrorSyscallLabels(event *model.KindlingEvent) (*model.AttributeMap, error) {
	labels := model.NewAttributeMap()
	ctx := event.GetCtx()
	if ctx == nil {
		return labels, fmt.Errorf("ctx is nil for event %s", event.Name)
	}

	threadinfo := ctx.GetThreadInfo()
	if threadinfo == nil {
		return labels, fmt.Errorf("threadinfo is nil for event %s", event.Name)
	}

	tid := (int64)(threadinfo.GetTid())
	pid := (int64)(threadinfo.GetPid())

	syscallName := event.GetName()
	containerId := threadinfo.GetContainerId()

	labels.AddStringValue(constlabels.Node, a.localNodeName)
	labels.AddIntValue(constlabels.Tid, tid)
	labels.AddIntValue(constlabels.Pid, pid)
	labels.AddStringValue(constlabels.SyscallName, syscallName)
	labels.AddStringValue(constlabels.ContainerId, containerId)

	return labels, nil
}

// Shutdown cleans all the resources used by the analyzer
func (a *ErrorSyscallAnalyzer) Shutdown() error {
	return nil
}

// Type returns the type of the analyzer
func (a *ErrorSyscallAnalyzer) Type() analyzer.Type {
	return ErrorSyscallTrace
}
