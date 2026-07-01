package hysteria

import (
	"testing"
	"time"

	xmetadata "github.com/go-gost/x/metadata"
)

func TestParseMetadata_KeepAliveDefaults(t *testing.T) {
	tests := []struct {
		name       string
		md         map[string]any
		wantPeriod time.Duration
	}{
		{
			name:       "nil metadata enables keepalive",
			md:         nil,
			wantPeriod: 10 * time.Second,
		},
		{
			name:       "absent key enables keepalive",
			md:         map[string]any{},
			wantPeriod: 10 * time.Second,
		},
		{
			name:       "explicit true enables keepalive",
			md:         map[string]any{"keepAlive": true},
			wantPeriod: 10 * time.Second,
		},
		{
			name:       "explicit true with custom ttl",
			md:         map[string]any{"keepAlive": true, "ttl": "30s"},
			wantPeriod: 30 * time.Second,
		},
		{
			name:       "explicit false disables keepalive",
			md:         map[string]any{"keepAlive": false},
			wantPeriod: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &hysteriaDialer{}
			md := xmetadata.NewMetadata(tt.md)
			if err := d.parseMetadata(md); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if d.md.keepAlivePeriod != tt.wantPeriod {
				t.Fatalf("keepAlivePeriod = %v, want %v", d.md.keepAlivePeriod, tt.wantPeriod)
			}
		})
	}
}

func TestParseMetadata_BandwidthNonNegative(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value any
		want  uint64
	}{
		{
			name:  "positive value passes through",
			key:   "bandwidth.tx",
			value: 1000,
			want:  1000,
		},
		{
			name:  "zero passes through",
			key:   "bandwidth.tx",
			value: 0,
			want:  0,
		},
		{
			name:  "negative value clamps to zero",
			key:   "bandwidth.tx",
			value: -1,
			want:  0,
		},
		{
			name:  "negative bandwidth rx clamps to zero",
			key:   "bandwidth.rx",
			value: -100,
			want:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &hysteriaDialer{}
			md := xmetadata.NewMetadata(map[string]any{tt.key: tt.value})
			if err := d.parseMetadata(md); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			var got uint64
			if tt.key == "bandwidth.tx" {
				got = d.md.bandwidthTx
			} else {
				got = d.md.bandwidthRx
			}
			if got != tt.want {
				t.Fatalf("bandwidth = %d, want %d", got, tt.want)
			}
		})
	}
}
