package tcppacketsanalyzer

import (
	"fmt"
	"time"

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

type tupleType int

const (
	Pair tupleType = iota
	Triple
	Quadruples
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
		constnames.TcpPacketCountsEvent,
		constnames.TcpAckDelayEvent,
	}
}

func (t *TcpPacketsAnalyzer) ConsumeEvent(event *model.KindlingEvent) error {
	var dataGroup *model.DataGroup
	var err error
	switch event.Name {
	case constnames.TcpHandshakeEvent:
		dataGroup, err = t.generateHandshakeRtt(event)
	case constnames.TcpPacketCountsEvent:
		dataGroup, err = t.generateTcpPacketCount(event)
	case constnames.TcpAckDelayEvent:
		dataGroup, err = t.generateTcpAckDelay(event)
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
	labels, err := t.getTupleLabels(event, Quadruples)
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

	// t.telemetry.Logger.Info(fmt.Sprintf("Event Output: %+v", model.TextKindlingEvent(event)))
	return model.NewDataGroup(constnames.TcpHandshakeRttGroupName, labels, uint64(startTime), metrics...), nil
}

func (t *TcpPacketsAnalyzer) generateTcpPacketCount(event *model.KindlingEvent) (*model.DataGroup, error) {
	//get tuple label:  (sip,dip)
	labels, err := t.getTupleLabels(event, Quadruples)
	if err != nil {
		return nil, err
	}
	// get delta info
	packetCounts := event.GetUintUserAttribute("packet_counts")
	directionType := event.GetIntUserAttribute("direction_type")

	metrics := make([]*model.Metric, 0, 2)
	metrics = append(metrics, model.NewIntMetric(constnames.TcpPacketCountsMetricName, int64(packetCounts)))
	metrics = append(metrics, model.NewIntMetric(constnames.TcpPacketCountsDirectionMetricName, int64(directionType)))

	// t.telemetry.Logger.Info(fmt.Sprintf("Event Output: %+v", model.TextKindlingEvent(event)))
	return model.NewDataGroup(constnames.TcpPacketCountsGroupName, labels, uint64(time.Now().Unix()), metrics...), nil
}

func (t *TcpPacketsAnalyzer) generateTcpAckDelay(event *model.KindlingEvent) (*model.DataGroup, error) {
	//get tuple label:  (sip,dip)
	labels, err := t.getTupleLabels(event, Quadruples)
	if err != nil {
		return nil, err
	}
	// get delta info
	dataCounts := event.GetUintUserAttribute("data_counts")
	acktimeDelta := event.GetIntUserAttribute("acktime_delta")
	startTime := event.GetUintUserAttribute("start_time")
	endTime := event.GetUintUserAttribute("end_time")

	metrics := make([]*model.Metric, 0, 4)
	metrics = append(metrics, model.NewIntMetric(constnames.TcpPacketDatacountsMetricName, int64(dataCounts)))
	metrics = append(metrics, model.NewIntMetric(constnames.TcpPacketStarttimeMetricName, int64(startTime)))
	metrics = append(metrics, model.NewIntMetric(constnames.TcpPacketEndtimeMetricName, int64(endTime)))
	metrics = append(metrics, model.NewIntMetric(constnames.TcpPacketAcktimeMetricName, int64(acktimeDelta)))

	// t.telemetry.Logger.Info(fmt.Sprintf("Event Output: %+v", model.TextKindlingEvent(event)))
	return model.NewDataGroup(constnames.TcpAckDelayGroupName, labels, uint64(startTime), metrics...), nil
}

func (t *TcpPacketsAnalyzer) getTupleLabels(event *model.KindlingEvent, tpType tupleType) (*model.AttributeMap, error) {
	sIp := event.GetUserAttribute("sip")
	dIp := event.GetUserAttribute("dip")
	labels := model.NewAttributeMap()
	if sIp == nil || dIp == nil {
		return nil, fmt.Errorf("one of sip or dip is nil for event %s", event.Name)
	}
	switch tpType {
	case Pair:
		break
	case Triple:
		dPort := event.GetUserAttribute("dport")
		if dPort == nil {
			return nil, fmt.Errorf("dport is nil for event %s", event.Name)
		}
		dPortUint := dPort.GetUintValue()
		labels.AddIntValue(constlabels.DstPort, int64(dPortUint))
	case Quadruples:
		sPort := event.GetUserAttribute("sport")
		dPort := event.GetUserAttribute("dport")
		if sPort == nil || dPort == nil {
			return nil, fmt.Errorf("sport or dport is nil for event %s", event.Name)
		}
		sPortUint := sPort.GetUintValue()
		dPortUint := dPort.GetUintValue()
		labels.AddIntValue(constlabels.DstPort, int64(dPortUint))
		labels.AddIntValue(constlabels.SrcPort, int64(sPortUint))
	}

	sIpString := model.IPLong2String(uint32(sIp.GetUintValue()))
	dIpString := model.IPLong2String(uint32(dIp.GetUintValue()))

	labels.AddStringValue(constlabels.SrcIp, sIpString)
	labels.AddStringValue(constlabels.DstIp, dIpString)

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
