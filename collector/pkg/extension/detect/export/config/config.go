package config

// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import (
	"net/http"
	"time"
)

type Config struct {
	HTTPClientSettings `mapstructure:",squash"` // squash ensures fields are correctly decoded in embedded struct.

	// QueueSettings      `mapstructure:"sending_queue"`
	// RetrySettings      `mapstructure:"retry_on_failure"`

	// The compression key for supported compression types within
	// collector. Currently the only supported mode is `gzip`.
	Compression string `mapstructure:"compression"`
}

// HTTPClientSettings defines settings for creating an HTTP client.
type HTTPClientSettings struct {
	// The target URL to send data to (e.g.: http://some.url:9411/v1/traces).
	Endpoint string `mapstructure:"endpoint"`

	// TLSSetting struct exposes TLS client configuration.
	TLSSetting TLSClientSetting `mapstructure:",squash"`

	// ReadBufferSize for HTTP client. See http.Transport.ReadBufferSize.
	ReadBufferSize int `mapstructure:"read_buffer_size"`

	// WriteBufferSize for HTTP client. See http.Transport.WriteBufferSize.
	WriteBufferSize int `mapstructure:"write_buffer_size"`

	// Timeout parameter configures `http.Client.Timeout`.
	Timeout time.Duration `mapstructure:"timeout,omitempty"`

	// Additional headers attached to each HTTP request sent by the client.
	// Existing header values are overwritten if collision happens.
	Headers map[string]string `mapstructure:"headers,omitempty"`

	// Custom Round Tripper to allow for individual components to intercept HTTP requests
	CustomRoundTripper func(next http.RoundTripper) (http.RoundTripper, error)
}

// ToClient creates an HTTP client.
func (hcs *HTTPClientSettings) ToClient() (*http.Client, error) {
	tlsCfg, err := hcs.TLSSetting.LoadTLSConfig()
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if tlsCfg != nil {
		transport.TLSClientConfig = tlsCfg
	}
	if hcs.ReadBufferSize > 0 {
		transport.ReadBufferSize = hcs.ReadBufferSize
	}
	if hcs.WriteBufferSize > 0 {
		transport.WriteBufferSize = hcs.WriteBufferSize
	}

	clientTransport := (http.RoundTripper)(transport)
	if len(hcs.Headers) > 0 {
		clientTransport = &headerRoundTripper{
			transport: transport,
			headers:   hcs.Headers,
		}
	}

	if hcs.CustomRoundTripper != nil {
		clientTransport, err = hcs.CustomRoundTripper(clientTransport)
		if err != nil {
			return nil, err
		}
	}

	return &http.Client{
		Transport: clientTransport,
		Timeout:   hcs.Timeout,
	}, nil
}

// Custom RoundTripper that add headers
type headerRoundTripper struct {
	transport http.RoundTripper
	headers   map[string]string
}

// RoundTrip is a custom RoundTripper that adds headers to the request.
func (interceptor *headerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	for k, v := range interceptor.headers {
		req.Header.Set(k, v)
	}
	// Send the request to next transport.
	return interceptor.transport.RoundTrip(req)
}
