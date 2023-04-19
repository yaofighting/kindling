module github.com/Kindling-project/kindling/collector

go 1.17

require (
	github.com/DataDog/ebpf v0.0.0-20220301203322-3fc9ab3b8daf
	github.com/Microsoft/go-winio v0.5.2 // indirect
	github.com/benbjohnson/clock v1.3.0 // indirect
	github.com/cenkalti/backoff/v4 v4.1.3
	github.com/docker/docker v20.10.17+incompatible
	github.com/elastic/gosigar v0.14.2
	github.com/florianl/go-conntrack v0.3.0
	github.com/gofrs/uuid v4.4.0+incompatible
	github.com/gogo/protobuf v1.3.2
	github.com/golang/mock v1.6.0
	github.com/golang/protobuf v1.5.2
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway v1.16.0
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hashicorp/golang-lru v0.5.4
	github.com/imdario/mergo v0.3.12 // indirect
	github.com/jaegertracing/jaeger v1.33.0
	github.com/mdlayher/netlink v1.6.0
	github.com/mitchellh/mapstructure v1.5.0
	github.com/onsi/gomega v1.17.0 // indirect
	github.com/opencontainers/image-spec v1.0.3-0.20211202183452-c5a74bcca799 // indirect
	github.com/orcaman/concurrent-map v0.0.0-20210501183033-44dafcb38ecc
	github.com/pkg/errors v0.9.1
	github.com/prometheus-community/pro-bing v0.1.0
	github.com/prometheus/client_golang v1.12.2
	github.com/prometheus/common v0.37.0 // indirect
	github.com/rs/cors v1.8.2
	github.com/shirou/gopsutil v3.21.11+incompatible
	github.com/spf13/cast v1.5.0
	github.com/spf13/viper v1.12.0
	github.com/stretchr/testify v1.8.0
	github.com/tklauser/go-sysconf v0.3.10 // indirect
	github.com/vishvananda/netns v0.0.0-20211101163701-50045581ed74
	github.com/yusufpapurcu/wmi v1.2.2 // indirect
	go.opencensus.io v0.23.0
	go.opentelemetry.io/otel v1.8.0
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc v0.25.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.3.0
	go.opentelemetry.io/otel/exporters/prometheus v0.31.0
	go.opentelemetry.io/otel/exporters/stdout/stdoutmetric v0.25.0
	go.opentelemetry.io/otel/exporters/stdout/stdouttrace v1.2.0
	go.opentelemetry.io/otel/metric v0.31.0
	go.opentelemetry.io/otel/sdk v1.8.0
	go.opentelemetry.io/otel/sdk/export/metric v0.25.0
	go.opentelemetry.io/otel/sdk/metric v0.25.0
	go.opentelemetry.io/otel/trace v1.8.0
	go.uber.org/multierr v1.7.0
	go.uber.org/zap v1.21.0
	golang.org/x/net v0.0.0-20220615171555-694bf12d69de
	golang.org/x/sys v0.0.0-20220615213510-4f61da869c0c
	google.golang.org/genproto v0.0.0-20220519153652-3a47de7e79bd
	google.golang.org/grpc v1.46.2
	google.golang.org/protobuf v1.28.0
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	k8s.io/api v0.22.5
	k8s.io/apimachinery v0.22.5
	k8s.io/apiserver v0.22.5 // indirect
	k8s.io/client-go v0.22.5
	k8s.io/component-base v0.22.5 // indirect
	k8s.io/cri-api v0.24.2
	k8s.io/kubernetes v1.24.2
)

replace (
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc => go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc v0.25.0
	go.opentelemetry.io/otel/exporters/prometheus => go.opentelemetry.io/otel/exporters/prometheus v0.25.0
	go.opentelemetry.io/otel/metric => go.opentelemetry.io/otel/metric v0.25.0
	go.opentelemetry.io/otel/sdk/metric => go.opentelemetry.io/otel/sdk/metric v0.25.0
	k8s.io/api => k8s.io/kubernetes/staging/src/k8s.io/api v0.0.0-20220503133649-4ce5a8954017
	k8s.io/apiextensions-apiserver => k8s.io/kubernetes/staging/src/k8s.io/apiextensions-apiserver v0.0.0-20220503133649-4ce5a8954017
	k8s.io/apimachinery => k8s.io/kubernetes/staging/src/k8s.io/apimachinery v0.0.0-20220503133649-4ce5a8954017
	k8s.io/apiserver => k8s.io/kubernetes/staging/src/k8s.io/apiserver v0.0.0-20220503133649-4ce5a8954017
	k8s.io/cli-runtime => k8s.io/kubernetes/staging/src/k8s.io/cli-runtime v0.0.0-20220503133649-4ce5a8954017
	k8s.io/client-go => k8s.io/kubernetes/staging/src/k8s.io/client-go v0.0.0-20220503133649-4ce5a8954017
	k8s.io/cloud-provider => k8s.io/kubernetes/staging/src/k8s.io/cloud-provider v0.0.0-20220503133649-4ce5a8954017
	k8s.io/cluster-bootstrap => k8s.io/kubernetes/staging/src/k8s.io/cluster-bootstrap v0.0.0-20220503133649-4ce5a8954017
	k8s.io/code-generator => k8s.io/kubernetes/staging/src/k8s.io/code-generator v0.0.0-20220503133649-4ce5a8954017
	k8s.io/component-base => k8s.io/kubernetes/staging/src/k8s.io/component-base v0.0.0-20220503133649-4ce5a8954017
	k8s.io/component-helpers => k8s.io/kubernetes/staging/src/k8s.io/component-helpers v0.0.0-20220503133649-4ce5a8954017
	k8s.io/controller-manager => k8s.io/kubernetes/staging/src/k8s.io/controller-manager v0.0.0-20220503133649-4ce5a8954017
	k8s.io/cri-api => k8s.io/kubernetes/staging/src/k8s.io/cri-api v0.0.0-20220503133649-4ce5a8954017
	k8s.io/csi-translation-lib => k8s.io/kubernetes/staging/src/k8s.io/csi-translation-lib v0.0.0-20220503133649-4ce5a8954017
	k8s.io/kube-aggregator => k8s.io/kubernetes/staging/src/k8s.io/kube-aggregator v0.0.0-20220503133649-4ce5a8954017
	k8s.io/kube-controller-manager => k8s.io/kubernetes/staging/src/k8s.io/kube-controller-manager v0.0.0-20220503133649-4ce5a8954017
	k8s.io/kube-proxy => k8s.io/kubernetes/staging/src/k8s.io/kube-proxy v0.0.0-20220503133649-4ce5a8954017
	k8s.io/kube-scheduler => k8s.io/kubernetes/staging/src/k8s.io/kube-scheduler v0.0.0-20220503133649-4ce5a8954017
	k8s.io/kubectl => k8s.io/kubernetes/staging/src/k8s.io/kubectl v0.0.0-20220503133649-4ce5a8954017
	k8s.io/kubelet => k8s.io/kubernetes/staging/src/k8s.io/kubelet v0.0.0-20220503133649-4ce5a8954017
	k8s.io/kubernetes => k8s.io/kubernetes v1.24.0
	k8s.io/legacy-cloud-providers => k8s.io/kubernetes/staging/src/k8s.io/legacy-cloud-providers v0.0.0-20220503133649-4ce5a8954017
	k8s.io/metrics => k8s.io/kubernetes/staging/src/k8s.io/metrics v0.0.0-20220503133649-4ce5a8954017
	k8s.io/mount-utils => k8s.io/kubernetes/staging/src/k8s.io/mount-utils v0.0.0-20220503133649-4ce5a8954017
	k8s.io/pod-security-admission => k8s.io/kubernetes/staging/src/k8s.io/pod-security-admission v0.0.0-20220503133649-4ce5a8954017
	k8s.io/sample-apiserver => k8s.io/kubernetes/staging/src/k8s.io/sample-apiserver v0.0.0-20220503133649-4ce5a8954017
)
