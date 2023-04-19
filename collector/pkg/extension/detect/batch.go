package detect

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/Kindling-project/kindling/collector/pkg/component"
	"github.com/Kindling-project/kindling/collector/pkg/extension/detect/export"
	"go.uber.org/zap"
)

const detectEndpoint = "/v1/detect"

type Batch struct {
	*BatchConfig
	logger    *component.TelemetryLogger
	exportCtx context.Context
	timer     *time.Timer

	newItem    chan *AvailabilityDetectReport
	batch      batcher
	shutdownC  chan struct{}
	goroutines sync.WaitGroup
}

type BatchConfig struct {
	// Timeout sets the time after which a batch will be sent regardless of size.
	BatchTimeout time.Duration `mapstructure:"batch_timeout"`
	// SendBatchSize is the size of a batch which after hit, will trigger it to be sent.
	SendBatchSize    uint32 `mapstructure:"send_batch_size"`
	SendBatchMaxSize uint32 `mapstructure:"send_batch_max_size"`
}

func (b *Batch) ReportStream() chan<- *AvailabilityDetectReport {
	return b.newItem
}

// Start is invoked during service startup.
func (b *Batch) Start(context.Context) error {
	b.goroutines.Add(1)
	go b.startProcessingCycle()
	return nil
}

// Shutdown is invoked during service shutdown.
func (b *Batch) Shutdown(context.Context) error {
	close(b.shutdownC)

	// Wait until all goroutines are done.
	b.goroutines.Wait()
	return nil
}

func (b *Batch) startProcessingCycle() {
	defer b.goroutines.Done()
	b.timer = time.NewTimer(b.BatchTimeout)
	for {
		select {
		case <-b.shutdownC:
		DONE:
			for {
				select {
				case item := <-b.newItem:
					b.processItem(item)
				default:
					break DONE
				}
			}
			// This is the close of the channel
			if b.batch.itemCount() > 0 {
				b.sendItems()
			}
			return
		case item := <-b.newItem:
			if item == nil {
				continue
			}
			b.processItem(item)
		case <-b.timer.C:
			if b.batch.itemCount() > 0 {
				b.sendItems()
			}
			b.resetTimer()
		}
	}
}

func (b *Batch) processItem(item *AvailabilityDetectReport) {
	b.batch.add(item)
	sent := false

	for b.batch.itemCount() >= b.SendBatchSize {
		sent = true
		b.sendItems()
	}

	if sent {
		b.stopTimer()
		b.resetTimer()
	}
}

func (b *Batch) stopTimer() {
	if !b.timer.Stop() {
		<-b.timer.C
	}
}

func (b *Batch) resetTimer() {
	b.timer.Reset(b.BatchTimeout)
}

func (b *Batch) sendItems() {
	if err := b.batch.export(b.exportCtx, b.SendBatchMaxSize); err != nil {
		b.logger.Warn("Sender failed", zap.Error(err))
	}
}

type batcher struct {
	Exporter export.HTTPExporter
	req      *detectReportsRequest

	count uint32
}

type detectReportsRequest struct {
	AgentInfo

	Reports []*AvailabilityDetectReport `json:""`
}

func (rs *detectReportsRequest) add(report *AvailabilityDetectReport) {
	rs.Reports = append(rs.Reports, report)
}

func (be *batcher) itemCount() uint32 {
	return be.count
}

func (be *batcher) add(report *AvailabilityDetectReport) {
	be.req.add(report)
	be.count++
}

func (be *batcher) export(context context.Context, sendBatchMaxSize uint32) error {
	if sendBatchMaxSize > 0 && be.itemCount() > sendBatchMaxSize {
		reqs := SplitReports(int(sendBatchMaxSize), be.req)
		be.count = be.count - sendBatchMaxSize
		bytes, _ := json.Marshal(reqs)
		return be.Exporter.Export(context, detectEndpoint, bytes)
	} else {
		bytes, _ := json.Marshal(be.req)
		be.req = &detectReportsRequest{
			Reports: make([]*AvailabilityDetectReport, 0, sendBatchMaxSize),
		}
		be.count = 0
		return be.Exporter.Export(context, detectEndpoint, bytes)
	}
}

func SplitReports(size int, src *detectReportsRequest) detectReportsRequest {
	if len(src.Reports) <= size {
		return *src
	}
	dest := detectReportsRequest{
		Reports: src.Reports[0:size],
	}
	src.Reports = src.Reports[size:]
	return dest
}
