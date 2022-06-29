package pgftmetricanalyzer

import (
	"fmt"

	"github.com/Kindling-project/kindling/collector/analyzer"
	"github.com/Kindling-project/kindling/collector/component"
	"github.com/Kindling-project/kindling/collector/consumer"
	"github.com/Kindling-project/kindling/collector/model"
	"github.com/Kindling-project/kindling/collector/model/constlabels"
	"github.com/Kindling-project/kindling/collector/model/constnames"
	"github.com/hashicorp/go-multierror"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	PgftMetric analyzer.Type = "pgftmetricanalyzer"
)

var consumableEvents = map[string]bool{
	constnames.PageFaultEvent: true,
} 

type PgftMetricAnalyzer struct {
	consumers []consumer.Consumer
	telemetry *component.TelemetryTools
}

func NewPgftMetricAnalyzer(cfg interface{}, telemetry *component.TelemetryTools, nextConsumers []consumer.Consumer) analyzer.Analyzer {
	retAnalyzer := &PgftMetricAnalyzer{
		consumers: nextConsumers,
		telemetry: telemetry,
	}
	return retAnalyzer
}

func (a *PgftMetricAnalyzer) Start() error {
	return nil
}

func (a *PgftMetricAnalyzer) ConsumableEvents() []string {
	return []string{
		constnames.PageFaultEvent,
	}
}

// ConsumeEvent gets the event from the previous component
func (a *PgftMetricAnalyzer) ConsumeEvent(event *model.KindlingEvent) error {
	_, ok := consumableEvents[event.Name]
	if !ok {
		return nil
	}
	var dataGroup *model.DataGroup
	var err error
	switch event.Name {
	case constnames.PageFaultEvent:
		dataGroup, err = a.generatePageFault(event)
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

func (a *PgftMetricAnalyzer) generatePageFault(event *model.KindlingEvent) (*model.DataGroup, error) {
	labels, err := a.getPageFaultLabels(event)
	if err != nil {
		return nil, err
	}

	pgftMaj := event.GetUserAttribute("pgft_maj")
	pgftMin := event.GetUserAttribute("pgft_min")
	if(pgftMaj == nil || pgftMin == nil){
		return nil, fmt.Errorf("the page fault major or minor value is null %s", event.Name)
	}
	ptMaj := pgftMaj.GetUintValue()
	ptMin := pgftMin.GetUintValue()

	dataMaj := model.NewIntMetric(constnames.PgftMajorMetricName, int64(ptMaj))
	dataMin := model.NewIntMetric(constnames.PgftMinorMetricName, int64(ptMin))
	var dataSlice []*model.Metric
	if ptMaj != 0{
		dataSlice = append(dataSlice, dataMaj)
	}
	if ptMin != 0 {
		dataSlice = append(dataSlice, dataMin)
	}

	return model.NewDataGroup(constnames.PgftMetricGroupName, labels, event.Timestamp, dataSlice...), nil
}

func (a *PgftMetricAnalyzer) getPageFaultLabels(event *model.KindlingEvent) (*model.AttributeMap, error) {

	labels := model.NewAttributeMap()
	ctx := event.GetCtx()
	if ctx == nil {
		return labels, fmt.Errorf("ctx is nil for event %s", event.Name)
	}

	threadinfo := ctx.GetThreadInfo()
	if threadinfo == nil {
		return labels, fmt.Errorf("threadinfo is nil for event %s", event.Name)
	}

	containerId := threadinfo.GetContainerId()
	containerName := threadinfo.GetContainerName()

	tid := (int64)(threadinfo.GetTid())
	pid := (int64)(threadinfo.GetPid())

	labels.AddIntValue(constlabels.Tid, tid)
	labels.AddIntValue(constlabels.Pid, pid)
	labels.AddStringValue(constlabels.ContainerId, containerId)
	labels.AddStringValue(constlabels.Container, containerName)

	return labels, nil
}

// Shutdown cleans all the resources used by the analyzer
func (a *PgftMetricAnalyzer) Shutdown() error {
	return nil
}

// Type returns the type of the analyzer
func (a *PgftMetricAnalyzer) Type() analyzer.Type {
	return PgftMetric
}
