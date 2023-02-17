package tcppacketsanalyzer

import (
	"fmt"

	"github.com/hashicorp/go-multierror"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/Kindling-project/kindling/collector/pkg/component"
	"github.com/Kindling-project/kindling/collector/pkg/component/analyzer"
	"github.com/Kindling-project/kindling/collector/pkg/component/consumer"
	conntrackerpackge "github.com/Kindling-project/kindling/collector/pkg/metadata/conntracker"
	"github.com/Kindling-project/kindling/collector/pkg/model"
	"github.com/Kindling-project/kindling/collector/pkg/model/constlabels"
	"github.com/Kindling-project/kindling/collector/pkg/model/constnames"
)

const (
	Type analyzer.Type = "tcppacketsanalyzer"
)

type TcpPacketsAnalyzer struct {
	consumers   []consumer.Consumer
	conntracker conntrackerpackge.Conntracker
	telemetry   *component.TelemetryTools
}

func New(_ interface{}, telemetry *component.TelemetryTools, nextConsumers []consumer.Consumer) analyzer.Analyzer {
	newAnalyzer := &TcpPacketsAnalyzer{
		consumers: nextConsumers,
		telemetry: telemetry,
	}
	conntracker, err := conntrackerpackge.NewConntracker(nil)
	if err != nil {
		telemetry.Logger.Warn("Conntracker cannot work as expected:", zap.Error(err))
	}
	newAnalyzer.conntracker = conntracker
	return newAnalyzer
}

func (t *TcpPacketsAnalyzer) Start() error {
	return nil
}

func (t *TcpPacketsAnalyzer) ConsumableEvents() []string {
	return []string{
		constnames.TcpHandshakeEvent,
	}
}

func (t *TcpPacketsAnalyzer) ConsumeEvent(event *model.KindlingEvent) error {
	var dataGroup *model.DataGroup
	var err error
	switch event.Name {
	case constnames.TcpHandshakeEvent:
		dataGroup, err = t.generateHandshakeRtt(event)
	default:
		return nil
	}
	if err != nil {
		if ce := t.telemetry.Logger.Check(zapcore.DebugLevel, "Event Skip, "); ce != nil {
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
	for _, nextConsumer := range t.consumers {
		err := nextConsumer.Consume(dataGroup)
		if err != nil {
			retError = multierror.Append(retError, err)
		}
	}
	return retError
}

func (t *TcpPacketsAnalyzer) generateHandshakeRtt(event *model.KindlingEvent) (*model.DataGroup, error) {
	//get tuple label:  (sip,dip,dport)
	labels, err := t.getTupleLabels(event)
	if err != nil {
		return nil, err
	}
	// get delta info
	dataCounts := event.GetUintUserAttribute("data_counts")
	synrttDelta := event.GetIntUserAttribute("synrtt_delta")
	ackrttDelta := event.GetIntUserAttribute("ackrtt_delta")
	startTime := event.GetUintUserAttribute("start_time")
	endTime := event.GetUintUserAttribute("end_time")

	metrics := make([]*model.Metric, 0, 4)
	metrics = append(metrics, model.NewIntMetric(constnames.TcpHandshakeDatacountsMetricName, int64(dataCounts)))
	metrics = append(metrics, model.NewIntMetric(constnames.TcpHandshakeStarttimeMetricName, int64(startTime)))
	metrics = append(metrics, model.NewIntMetric(constnames.TcpHandshakeEndtimeMetricName, int64(endTime)))
	if int64(synrttDelta) != -1 { //synrtt delta is valid
		metrics = append(metrics, model.NewIntMetric(constnames.TcpHandshakeSynRttMetricName, int64(synrttDelta)))
	} else { //ackrtt delta is valid
		metrics = append(metrics, model.NewIntMetric(constnames.TcpHandshakeAckRttMetricName, int64(ackrttDelta)))
	}

	//t.telemetry.Logger.Info(fmt.Sprintf("Event Output: %+v", model.TextKindlingEvent(event)))
	return model.NewDataGroup(constnames.TcpHandshakeRttGroupName, labels, uint64(startTime), metrics...), nil
}

func (t *TcpPacketsAnalyzer) getTupleLabels(event *model.KindlingEvent) (*model.AttributeMap, error) {
	//sIp is the client-IP that initiates the first handshake
	sIp := event.GetUserAttribute("sip")
	dIp := event.GetUserAttribute("dip")
	dPort := event.GetUserAttribute("dport")

	if sIp == nil || dIp == nil || dPort == nil {
		return nil, fmt.Errorf("one of sip or dip or dport is nil for event %s", event.Name)
	}
	sIpString := model.IPLong2String(uint32(sIp.GetUintValue()))
	dIpString := model.IPLong2String(uint32(dIp.GetUintValue()))
	dPortUint := dPort.GetUintValue()

	labels := model.NewAttributeMap()
	labels.AddStringValue(constlabels.SrcIp, sIpString)
	labels.AddStringValue(constlabels.DstIp, dIpString)
	labels.AddIntValue(constlabels.DstPort, int64(dPortUint))

	return labels, nil
}

// Shutdown cleans all the resources used by the analyzer
func (t *TcpPacketsAnalyzer) Shutdown() error {
	return nil
}

// Type returns the type of the analyzer
func (t *TcpPacketsAnalyzer) Type() analyzer.Type {
	return Type
}
