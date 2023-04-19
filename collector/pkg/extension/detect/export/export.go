package export

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/Kindling-project/kindling/collector/pkg/extension/detect/export/config"
	"github.com/Kindling-project/kindling/collector/pkg/extension/detect/export/middleware"

	"github.com/gofrs/uuid"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/proto"
)

const (
	headerRetryAfter         = "Retry-After"
	maxHTTPResponseReadBytes = 64 * 1024
)

type HTTPExporter struct {
	cfg    config.HTTPClientSettings
	client *http.Client
}

func NewHTTPExporter(cfg *config.Config) (*HTTPExporter, error) {
	uuid, _ := uuid.NewV4()
	uuid.String()
	client, err := cfg.HTTPClientSettings.ToClient()
	if err != nil {
		return nil, err
	}

	if cfg.Compression != "" {
		if strings.ToLower(cfg.Compression) == "gzip" {
			client.Transport = middleware.NewCompressRoundTripper(client.Transport)
		} else {
			return nil, fmt.Errorf("unsupported compression type %q", cfg.Compression)
		}
	}

	return &HTTPExporter{
		cfg:    cfg.HTTPClientSettings,
		client: client,
	}, nil
}

func (e *HTTPExporter) Export(ctx context.Context, url string, request []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s%s", e.cfg.Endpoint, url), bytes.NewReader(request))
	if err != nil {
		return Permanent(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make an HTTP request to endpoint %s: %w", url, err)
	}

	defer func() {
		// Discard any remaining response body when we are done reading.
		io.CopyN(ioutil.Discard, resp.Body, maxHTTPResponseReadBytes) // nolint:errcheck
		resp.Body.Close()
	}()

	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		// Request is successful.
		return nil
	}

	respStatus := readResponse(resp)

	// Format the error message. Use the status if it is present in the response.
	var formattedErr error
	if respStatus != nil {
		formattedErr = fmt.Errorf(
			"error exporting items, request to %s responded with HTTP Status Code %d, Message=%s, Details=%v",
			url, resp.StatusCode, respStatus.Message, respStatus.Details)
	} else {
		formattedErr = fmt.Errorf(
			"error exporting items, request to %s responded with HTTP Status Code %d",
			url, resp.StatusCode)
	}

	// Check if the server is overwhelmed.
	// See spec https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/protocol/otlp.md#throttling-1

	// TOOD RetryQueue
	// if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
	// 	// Fallback to 0 if the Retry-After header is not present. This will trigger the
	// 	// default backoff policy by our caller (retry handler).
	// 	retryAfter := 0
	// 	if val := resp.Header.Get(headerRetryAfter); val != "" {
	// 		if seconds, err2 := strconv.Atoi(val); err2 == nil {
	// 			retryAfter = seconds
	// 		}
	// 	}
	// 	// Indicate to our caller to pause for the specified number of seconds.
	// 	return config.NewThrottleRetry(formattedErr, time.Duration(retryAfter)*time.Second)
	// }

	if resp.StatusCode == http.StatusBadRequest {
		// Report the failure as permanent if the server thinks the request is malformed.
		return Permanent(formattedErr)
	}

	// All other errors are retryable, so don't wrap them in consumererror.Permanent().
	return formattedErr
}

// Read the response and decode the status.Status from the body.
// Returns nil if the response is empty or cannot be decoded.
func readResponse(resp *http.Response) *status.Status {
	var respStatus *status.Status
	if resp.StatusCode >= 400 && resp.StatusCode <= 599 {
		// Request failed. Read the body. OTLP spec says:
		// "Response body for all HTTP 4xx and HTTP 5xx responses MUST be a
		// Protobuf-encoded Status message that describes the problem."
		maxRead := resp.ContentLength
		if maxRead == -1 || maxRead > maxHTTPResponseReadBytes {
			maxRead = maxHTTPResponseReadBytes
		}
		respBytes := make([]byte, maxRead)
		n, err := io.ReadFull(resp.Body, respBytes)
		if err == nil && n > 0 {
			// Decode it as Status struct. See https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/protocol/otlp.md#failures
			respStatus = &status.Status{}
			err = proto.Unmarshal(respBytes, respStatus)
			if err != nil {
				respStatus = nil
			}
		}
	}

	return respStatus
}

// permanent is an error that will be always returned if its source
// receives the same inputs.
type permanent struct {
	err error
}

// Permanent wraps an error to indicate that it is a permanent error, i.e.: an
// error that will be always returned if its source receives the same inputs.
func Permanent(err error) error {
	return permanent{err: err}
}

func (p permanent) Error() string {
	return "Permanent error: " + p.err.Error()
}

// Unwrap returns the wrapped error for functions Is and As in standard package errors.
func (p permanent) Unwrap() error {
	return p.err
}

// IsPermanent checks if an error was wrapped with the Permanent function, that
// is used to indicate that a given error will always be returned in the case
// that its sources receives the same input.
func IsPermanent(err error) bool {
	if err == nil {
		return false
	}
	return errors.As(err, &permanent{})
}
