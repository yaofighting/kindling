package networkpkganalyzer

import (
	"fmt"
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
	NETWORKPKGANALYZER analyzer.Type = "networkpkganalyzer"
)

type NetworkPkgAnalyzer struct {
	consumers []consumer.Consumer
	telemetry *component.TelemetryTools
}

var events []string

func NewNetworkPkgAnalyzer(cfg interface{}, telemetry *component.TelemetryTools, nextConsumers []consumer.Consumer) analyzer.Analyzer {
	retAnalyzer := &NetworkPkgAnalyzer{
		consumers: nextConsumers,
		telemetry: telemetry,
	}
	return retAnalyzer
}

func (a *NetworkPkgAnalyzer) Start() error {
	return nil
}

// ConsumeEvent gets the event from the previous component
func (a *NetworkPkgAnalyzer) ConsumeEvent(event *model.KindlingEvent) error {
	var dataGroup *model.DataGroup
	var err error

	dataGroup, err = a.generateNetworkPackage(event)
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

func (a *NetworkPkgAnalyzer) getTupleLabels(event *model.KindlingEvent) (*model.AttributeMap, error) {
	// Note: Here sIp/dIp doesn't mean IP from client/server side for sure.
	// sIp stands for the IP which sends tcp flow.
	sIp := event.GetUserAttribute("sip")
	sPort := event.GetUserAttribute("sport")
	dIp := event.GetUserAttribute("dip")
	dPort := event.GetUserAttribute("dport")

	if sIp == nil || sPort == nil || dIp == nil || dPort == nil {
		return nil, fmt.Errorf("one of sip or dip or dport is nil for event %s", event.Name)
	}
	sIpString := model.IPLong2String(uint32(sIp.GetUintValue()))
	sPortUint := sPort.GetUintValue()
	dIpString := model.IPLong2String(uint32(dIp.GetUintValue()))
	dPortUint := dPort.GetUintValue()

	labels := model.NewAttributeMap()
	labels.AddStringValue(constlabels.SrcIp, sIpString)
	labels.AddIntValue(constlabels.SrcPort, int64(sPortUint))
	labels.AddStringValue(constlabels.DstIp, dIpString)
	labels.AddIntValue(constlabels.DstPort, int64(dPortUint))

	return labels, nil
}

func (a *NetworkPkgAnalyzer) generateNetworkPackage(event *model.KindlingEvent) (*model.DataGroup, error) {
	labels, err := a.getTupleLabels(event)
	if err != nil {
		return nil, err
	}
	ifIndex := event.GetStringUserAttribute("ifindex")
	if ifIndex == "" {
		return nil, fmt.Errorf("the ifindex value is null, wo don't get return value for %s", event.Name)
	}
	labels.AddStringValue(constlabels.IfIndex, ifIndex)

	return model.NewDataGroup(constnames.NetworkPackageGroupName, labels, event.Timestamp, nil), nil
}

func (a *NetworkPkgAnalyzer) SetSubEvents(params map[string]string) {
}

func (a *NetworkPkgAnalyzer) ConsumableEvents() []string {
	events = append(events, constnames.PodNetTrackEvent)
	return events
}

// Shutdown cleans all the resources used by the analyzer
func (a *NetworkPkgAnalyzer) Shutdown() error {
	return nil
}

// Type returns the type of the analyzer
func (a *NetworkPkgAnalyzer) Type() analyzer.Type {
	return NETWORKPKGANALYZER
}
