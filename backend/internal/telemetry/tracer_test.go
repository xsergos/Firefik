package telemetry

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace/noop"
)

func withEnv(t *testing.T, env map[string]string, fn func()) {
	t.Helper()
	orig := make(map[string]string, len(env))
	for k, v := range env {
		orig[k] = lookupEnvOrEmpty(k)
		t.Setenv(k, v)
	}
	defer func() {
		for k, v := range orig {
			if v == "" {
				t.Setenv(k, "")
			} else {
				t.Setenv(k, v)
			}
		}
	}()
	fn()
}

func lookupEnvOrEmpty(k string) string {
	return ""
}

func noopLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestInitDisabledByDefault(t *testing.T) {
	withEnv(t, map[string]string{"FIREFIK_OTEL_ENABLED": ""}, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		shutdown, err := Init(ctx, "test", noopLogger())
		if err != nil {
			t.Fatalf("Init returned error when disabled: %v", err)
		}
		if shutdown == nil {
			t.Fatal("Init returned nil Shutdown")
		}
		if err := shutdown(ctx); err != nil {
			t.Fatalf("Shutdown returned error on noop: %v", err)
		}
		if _, ok := otel.GetTracerProvider().(noop.TracerProvider); !ok {
			t.Errorf("expected noop.TracerProvider, got %T", otel.GetTracerProvider())
		}
	})
}

func TestSampleRatioBoundaries(t *testing.T) {
	cases := []struct {
		raw  string
		want float64
	}{
		{"", 1.0},
		{"0.5", 0.5},
		{"0.0", 0.0},
		{"1.0", 1.0},
		{"-0.1", 1.0},
		{"1.5", 1.0},
		{"abc", 1.0},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			t.Setenv("FIREFIK_OTEL_SAMPLE_RATIO", tc.raw)
			got := sampleRatio()
			if got != tc.want {
				t.Errorf("sampleRatio(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

func TestEndpointDefault(t *testing.T) {
	t.Setenv("FIREFIK_OTEL_ENDPOINT", "")
	if got := endpoint(); got != "localhost:4317" {
		t.Errorf("endpoint default = %q, want localhost:4317", got)
	}
}

func TestEndpointOverride(t *testing.T) {
	t.Setenv("FIREFIK_OTEL_ENDPOINT", "otel-collector:4319")
	if got := endpoint(); got != "otel-collector:4319" {
		t.Errorf("endpoint override = %q", got)
	}
}

func TestServiceNameDefault(t *testing.T) {
	t.Setenv("FIREFIK_OTEL_SERVICE_NAME", "")
	if got := serviceName(); got != "firefik" {
		t.Errorf("serviceName default = %q", got)
	}
}

func TestServiceNameOverride(t *testing.T) {
	t.Setenv("FIREFIK_OTEL_SERVICE_NAME", "firefik-staging")
	if got := serviceName(); got != "firefik-staging" {
		t.Errorf("serviceName = %q", got)
	}
}

func TestProtocolDefault(t *testing.T) {
	t.Setenv("FIREFIK_OTEL_PROTOCOL", "")
	if got := protocol(); got != "grpc" {
		t.Errorf("protocol default = %q", got)
	}
}

func TestProtocolOverride(t *testing.T) {
	t.Setenv("FIREFIK_OTEL_PROTOCOL", "http/protobuf")
	if got := protocol(); got != "http/protobuf" {
		t.Errorf("protocol override = %q", got)
	}
}

func TestEnabledParsing(t *testing.T) {
	cases := []struct {
		raw  string
		want bool
	}{
		{"", false},
		{"false", false},
		{"no", false},
		{"0", false},
		{"true", true},
		{"yes", true},
		{"1", true},
		{"TRUE", false},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			t.Setenv("FIREFIK_OTEL_ENABLED", tc.raw)
			if got := enabled(); got != tc.want {
				t.Errorf("enabled(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

func TestTracerAlwaysReturnsNonNil(t *testing.T) {
	if Tracer() == nil {
		t.Fatal("Tracer() returned nil")
	}
}

func TestEndpointForProtocolDefaults(t *testing.T) {
	t.Setenv("FIREFIK_OTEL_ENDPOINT", "")
	cases := []struct {
		proto, want string
	}{
		{"grpc", "localhost:4317"},
		{"http", "localhost:4318"},
		{"http/protobuf", "localhost:4318"},
		{"", "localhost:4317"},
	}
	for _, tc := range cases {
		t.Run(tc.proto, func(t *testing.T) {
			got := endpointForProtocol(tc.proto)
			if got != tc.want {
				t.Errorf("endpointForProtocol(%q) = %q, want %q", tc.proto, got, tc.want)
			}
		})
	}
}

func TestEndpointOverrideBeatsProtocolDefault(t *testing.T) {
	t.Setenv("FIREFIK_OTEL_ENDPOINT", "custom:9999")
	if got := endpointForProtocol("http"); got != "custom:9999" {
		t.Errorf("endpointForProtocol(http)=%q when FIREFIK_OTEL_ENDPOINT is set", got)
	}
}

func TestValidateSampleRatioInvalid(t *testing.T) {
	cases := []struct {
		raw       string
		wantValid bool
	}{
		{"", true},
		{"0", true},
		{"1", true},
		{"0.1", true},
		{"abc", false},
		{"-0.1", false},
		{"2", false},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			t.Setenv("FIREFIK_OTEL_SAMPLE_RATIO", tc.raw)
			_, _, valid := validateSampleRatio()
			if valid != tc.wantValid {
				t.Errorf("valid=%v want %v (raw=%q)", valid, tc.wantValid, tc.raw)
			}
		})
	}
}
