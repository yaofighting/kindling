package analyzer

import (
	"errors"

	"github.com/hashicorp/go-multierror"
	"go.uber.org/zap"
)

const ConsumeAllEvents = "consumeAllEvents"

type Manager struct {
	// allAnalyzers contains all the analyzers managed
	allAnalyzers []Analyzer
	// consumeAllEventsAnalyzers contains the analyzers that are able to consume all events
	consumeAllEventsAnalyzers []Analyzer
	// eventAnalyzersMap maps the event names and the analyzers
	eventAnalyzersMap map[string][]Analyzer
}

func NewManager(analyzers ...Analyzer) (*Manager, error) {
	if len(analyzers) == 0 {
		return nil, errors.New("no analyzers found, but must provide at least one analyzer")
	}
	analyzerMap := make(map[string][]Analyzer)
	consumeAllEventsAnalyzers := make([]Analyzer, 0)
	for _, analyzer := range analyzers {
		consumableEvents := analyzer.ConsumableEvents()
		for _, event := range consumableEvents {
			if event == ConsumeAllEvents {
				consumeAllEventsAnalyzers = append(consumeAllEventsAnalyzers, analyzer)
			} else {
				analyzerSlice, ok := analyzerMap[event]
				if !ok {
					analyzerSlice = make([]Analyzer, 0)
				}
				analyzerSlice = append(analyzerSlice, analyzer)
				analyzerMap[event] = analyzerSlice
			}
		}
	}
	// Put all analyzers that are able to consume all events into the map
	// to avoid appending new slice when getting analyzers from the map.
	for key, value := range analyzerMap {
		for _, analyzer := range consumeAllEventsAnalyzers {
			analyzerMap[key] = append(value, analyzer)
		}
	}

	return &Manager{
		allAnalyzers:              analyzers,
		eventAnalyzersMap:         analyzerMap,
		consumeAllEventsAnalyzers: consumeAllEventsAnalyzers,
	}, nil
}

func (m *Manager) UpdateAnalyerMap(analyzers ...Analyzer) {
	for _, analyzer := range analyzers {
		consumableEvents := analyzer.ConsumableEvents()
		for _, event := range consumableEvents {
			if event != ConsumeAllEvents {
				analyzerSlice, ok := m.eventAnalyzersMap[event]
				if !ok {
					analyzerSlice = make([]Analyzer, 0)
				}
				analyzerSlice = append(analyzerSlice, analyzer)
				m.eventAnalyzersMap[event] = analyzerSlice
			}
		}
	}
}

func (m *Manager) StartAll(logger *zap.Logger) error {
	for _, analyzer := range m.allAnalyzers {
		logger.Sugar().Infof("Starting analyzer [%s]", analyzer.Type())
		err := analyzer.Start()
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) ShutdownAll(logger *zap.Logger) error {
	var retErr error = nil
	for _, analyzer := range m.allAnalyzers {
		logger.Sugar().Infof("Shutdown analyzer [%s]", analyzer.Type())
		err := analyzer.Shutdown()
		if err != nil {
			retErr = multierror.Append(retErr, err)
		}
	}
	return retErr
}

// GetConsumableAnalyzers returns the analyzers according to the input eventName.
// Note this method is called in very high frequency, so the performance is important.
func (m *Manager) GetConsumableAnalyzers(eventName string) []Analyzer {
	analyzers, ok := m.eventAnalyzersMap[eventName]
	if ok {
		// It's unnecessary to look up into consumeAllEventsAnalyzers since we have
		// put this kind of analyzers into the map. This could avoid appending new
		// slice.
		return analyzers
	} else {
		return m.consumeAllEventsAnalyzers
	}
}
