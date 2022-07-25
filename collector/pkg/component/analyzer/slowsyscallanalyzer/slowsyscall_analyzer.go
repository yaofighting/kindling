package slowsyscallanalyzer

import (
	"fmt"
	"os"

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
	SlowSyscallTrace analyzer.Type = "slowsyscallanalyzer"
)

type SlowSyscallAnalyzer struct {
	consumers []consumer.Consumer
	telemetry *component.TelemetryTools
}

func NewSlowSyscallAnalyzer(cfg interface{}, telemetry *component.TelemetryTools, nextConsumers []consumer.Consumer) analyzer.Analyzer {
	retAnalyzer := &SlowSyscallAnalyzer{
		consumers: nextConsumers,
		telemetry: telemetry,
	}
	return retAnalyzer
}

func (a *SlowSyscallAnalyzer) Start() error {
	return nil
}

func (a *SlowSyscallAnalyzer) ConsumableEvents() []string {
	return []string{
		constnames.SlowSyscallEvent,
	}
}

// ConsumeEvent gets the event from the previous component
func (a *SlowSyscallAnalyzer) ConsumeEvent(event *model.KindlingEvent) error {
	var dataGroup *model.DataGroup
	var err error
	if event.IsSlowSyscall() {
		dataGroup, err = a.generateSlowSyscall(event)
	}

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

func (a *SlowSyscallAnalyzer) generateSlowSyscall(event *model.KindlingEvent) (*model.DataGroup, error) {
	labels, err := a.getSlowSyscallLabels(event)
	if err != nil {
		return nil, err
	}

	dataLatency := event.GetUserAttribute("latency")
	if dataLatency == nil {
		return nil, fmt.Errorf("slow syscall: the latency value is nil %s", event.Name)
	}

	latency := dataLatency.GetUintValue()

	latencyTrace := model.NewIntMetric(constnames.PgftMajorMetricName, int64(latency))

	return model.NewDataGroup(constnames.SlowSyscallGroupName, labels, event.Timestamp, latencyTrace), nil
}

func getHostNameFromEnv() (string, error) {
	value, ok := os.LookupEnv("MY_NODE_NAME")
	if !ok {
		return "unknown", fmt.Errorf("MY_NODE_NAME is not found in env variable which will be set unknown")
	}
	return value, nil
}

func (a *SlowSyscallAnalyzer) getSlowSyscallLabels(event *model.KindlingEvent) (*model.AttributeMap, error) {

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

	var localNodeName string
	var err error
	if localNodeName, err = getHostNameFromEnv(); err != nil {
		return labels, fmt.Errorf("localName not found with %s", event.Name)
	}

	labels.AddStringValue(constlabels.Node, localNodeName)
	labels.AddIntValue(constlabels.Tid, tid)
	labels.AddIntValue(constlabels.Pid, pid)
	labels.AddStringValue(constlabels.SyscallName, syscallName)
	labels.AddStringValue(constlabels.ContainerId, containerId)

	return labels, nil
}

// Shutdown cleans all the resources used by the analyzer
func (a *SlowSyscallAnalyzer) Shutdown() error {
	return nil
}

// Type returns the type of the analyzer
func (a *SlowSyscallAnalyzer) Type() analyzer.Type {
	return SlowSyscallTrace
}
