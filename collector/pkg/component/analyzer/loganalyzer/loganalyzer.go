package loganalyzer

import (
	"github.com/Kindling-project/kindling/collector/pkg/component"
	"github.com/Kindling-project/kindling/collector/pkg/component/analyzer"
	"github.com/Kindling-project/kindling/collector/pkg/component/consumer"
	"github.com/Kindling-project/kindling/collector/pkg/model"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const Type analyzer.Type = "loganalyzer"

type LogAnalyzer struct {
	cfg           *Config
	nextConsumers []consumer.Consumer
	telemetry     *component.TelemetryTools
}

func New(cfg interface{}, telemetry *component.TelemetryTools, consumer []consumer.Consumer) analyzer.Analyzer {
	config, ok := cfg.(*Config)
	if !ok {
		telemetry.Logger.Panic("Cannot convert loganalyzer config")
	}
	return &LogAnalyzer{
		cfg:           config,
		nextConsumers: consumer,
		telemetry:     telemetry,
	}
}

func (a *LogAnalyzer) Start() error {
	return nil
}

func (a *LogAnalyzer) ConsumeEvent(event *model.KindlingEvent) error {
	if ce := a.telemetry.Logger.Check(zapcore.InfoLevel, "Receive event"); ce != nil {
		ce.Write(
			zap.String("event", event.String()),
		)
	}
	for _, nextConsumer := range a.nextConsumers {
		nextConsumer.Consume(&model.DataGroup{})
	}
	return nil
}

func (a *LogAnalyzer) Shutdown() error {
	return nil
}

func (a *LogAnalyzer) Type() analyzer.Type {
	return Type
}

func (a *LogAnalyzer) ConsumableEvents() []string {
	return []string{analyzer.ConsumeAllEvents}
}
func (a *LogAnalyzer) SetSubEvents(params map[string]string) {

}

type Config struct {
}
