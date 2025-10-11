package wireguard

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewEndpointResolver(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		settings ResolverSettings
		expected ResolverSettings
	}{
		{
			name: "default settings",
			settings: ResolverSettings{
				Hostname: "example.com",
				Port:     51820,
			},
			expected: ResolverSettings{
				Hostname:    "example.com",
				Port:        51820,
				MinInterval: 60 * time.Second,
			},
		},
		{
			name: "custom settings",
			settings: ResolverSettings{
				Hostname:        "test.example.com",
				Port:            8080,
				ResolveInterval: 5 * time.Minute,
				DNSServer:       "8.8.8.8",
				UseTTL:          true,
				MinInterval:     30 * time.Second,
			},
			expected: ResolverSettings{
				Hostname:        "test.example.com",
				Port:            8080,
				ResolveInterval: 5 * time.Minute,
				DNSServer:       "8.8.8.8",
				UseTTL:          true,
				MinInterval:     30 * time.Second,
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := &mockLogger{}
			resolver := NewEndpointResolver(tt.settings, logger)

			assert.Equal(t, tt.expected.Hostname, resolver.hostname)
			assert.Equal(t, tt.expected.Port, resolver.port)
			assert.Equal(t, tt.expected.ResolveInterval, resolver.resolveInterval)
			assert.Equal(t, tt.expected.MinInterval, resolver.minInterval)
			assert.Equal(t, tt.expected.UseTTL, resolver.useTTL)

			if tt.expected.DNSServer != "" {
				assert.Equal(t, tt.expected.DNSServer, resolver.dnsServer)
			} else {
				assert.Equal(t, "1.1.1.1", resolver.dnsServer) // Default
			}
		})
	}
}

func TestEndpointResolver_selectPreferredIP(t *testing.T) {
	t.Parallel()

	logger := &mockLogger{}
	resolver := NewEndpointResolver(ResolverSettings{
		Hostname: "example.com",
		Port:     51820,
	}, logger)

	tests := []struct {
		name     string
		ips      []netip.Addr
		expected netip.Addr
	}{
		{
			name:     "empty list",
			ips:      []netip.Addr{},
			expected: netip.Addr{},
		},
		{
			name: "single IPv4",
			ips: []netip.Addr{
				netip.MustParseAddr("192.168.1.1"),
			},
			expected: netip.MustParseAddr("192.168.1.1"),
		},
		{
			name: "single IPv6",
			ips: []netip.Addr{
				netip.MustParseAddr("2001:db8::1"),
			},
			expected: netip.MustParseAddr("2001:db8::1"),
		},
		{
			name: "IPv6 preferred over IPv4",
			ips: []netip.Addr{
				netip.MustParseAddr("192.168.1.1"),
				netip.MustParseAddr("2001:db8::1"),
				netip.MustParseAddr("192.168.1.2"),
			},
			expected: netip.MustParseAddr("2001:db8::1"),
		},
		{
			name: "multiple IPv6 addresses - sorted selection",
			ips: []netip.Addr{
				netip.MustParseAddr("2001:db8::2"),
				netip.MustParseAddr("2001:db8::1"),
				netip.MustParseAddr("192.168.1.1"),
			},
			expected: netip.MustParseAddr("2001:db8::1"), // Sorted, first IPv6
		},
		{
			name: "multiple IPv4 addresses - sorted selection",
			ips: []netip.Addr{
				netip.MustParseAddr("192.168.1.2"),
				netip.MustParseAddr("192.168.1.1"),
				netip.MustParseAddr("10.0.0.1"),
			},
			expected: netip.MustParseAddr("10.0.0.1"), // Sorted, first IPv4
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := resolver.selectPreferredIP(tt.ips)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEndpointResolver_ResolveMultipleIPs(t *testing.T) {
	t.Parallel()

	// This test requires a real DNS resolution, so we'll use a known hostname
	// Skip if no network connectivity
	if testing.Short() {
		t.Skip("Skipping network-dependent test in short mode")
	}

	logger := &mockLogger{}
	resolver := NewEndpointResolver(ResolverSettings{
		Hostname: "cloudflare.com", // Known to have both IPv4 and IPv6
		Port:     443,
	}, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ips, err := resolver.ResolveMultipleIPs(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, ips)

	// Verify IPv6 addresses come first, then IPv4
	var foundIPv4, foundIPv6 bool
	var ipv6Index, ipv4Index int = -1, -1

	for i, ip := range ips {
		if ip.Is6() && !foundIPv6 {
			foundIPv6 = true
			ipv6Index = i
		}
		if ip.Is4() && !foundIPv4 {
			foundIPv4 = true
			ipv4Index = i
		}
	}

	// If both IPv4 and IPv6 are present, IPv6 should come first
	if foundIPv4 && foundIPv6 {
		assert.Less(t, ipv6Index, ipv4Index, "IPv6 addresses should come before IPv4 addresses")
	}
}

func TestEndpointResolver_ResolveInitial(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("Skipping network-dependent test in short mode")
	}

	tests := []struct {
		name        string
		hostname    string
		expectError bool
	}{
		{
			name:        "valid hostname",
			hostname:    "cloudflare.com",
			expectError: false,
		},
		{
			name:        "invalid hostname",
			hostname:    "this-hostname-should-not-exist-12345.invalid",
			expectError: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := &mockLogger{}
			resolver := NewEndpointResolver(ResolverSettings{
				Hostname: tt.hostname,
				Port:     443,
			}, logger)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			endpoint, err := resolver.ResolveInitial(ctx)

			if tt.expectError {
				assert.Error(t, err)
				assert.False(t, endpoint.IsValid())
			} else {
				assert.NoError(t, err)
				assert.True(t, endpoint.IsValid())
				assert.Equal(t, uint16(443), endpoint.Port())
			}
		})
	}
}

func TestEndpointResolver_GetCurrentEndpoint(t *testing.T) {
	t.Parallel()

	logger := &mockLogger{}
	resolver := NewEndpointResolver(ResolverSettings{
		Hostname: "example.com",
		Port:     51820,
	}, logger)

	// Initially should return invalid endpoint
	endpoint := resolver.GetCurrentEndpoint()
	assert.False(t, endpoint.IsValid())

	// Set a current IP
	testIP := netip.MustParseAddr("192.168.1.1")
	resolver.mu.Lock()
	resolver.currentIP = testIP
	resolver.mu.Unlock()

	// Should return the set IP with correct port
	endpoint = resolver.GetCurrentEndpoint()
	assert.True(t, endpoint.IsValid())
	assert.Equal(t, testIP, endpoint.Addr())
	assert.Equal(t, uint16(51820), endpoint.Port())
}

func TestEndpointResolver_getNextResolveInterval(t *testing.T) {
	t.Parallel()

	logger := &mockLogger{}

	tests := []struct {
		name            string
		useTTL          bool
		lastTTL         time.Duration
		resolveInterval time.Duration
		minInterval     time.Duration
		expected        time.Duration
	}{
		{
			name:            "use configured interval when TTL disabled",
			useTTL:          false,
			lastTTL:         30 * time.Second,
			resolveInterval: 5 * time.Minute,
			minInterval:     60 * time.Second,
			expected:        5 * time.Minute,
		},
		{
			name:            "use min interval when no configured interval",
			useTTL:          false,
			lastTTL:         30 * time.Second,
			resolveInterval: 0,
			minInterval:     60 * time.Second,
			expected:        60 * time.Second,
		},
		{
			name:            "use TTL when enabled and available",
			useTTL:          true,
			lastTTL:         2 * time.Minute,
			resolveInterval: 5 * time.Minute,
			minInterval:     60 * time.Second,
			expected:        2 * time.Minute,
		},
		{
			name:            "enforce minimum interval with TTL",
			useTTL:          true,
			lastTTL:         30 * time.Second,
			resolveInterval: 5 * time.Minute,
			minInterval:     60 * time.Second,
			expected:        60 * time.Second,
		},
		{
			name:            "fallback to configured when TTL enabled but not available",
			useTTL:          true,
			lastTTL:         0,
			resolveInterval: 3 * time.Minute,
			minInterval:     60 * time.Second,
			expected:        3 * time.Minute,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			resolver := NewEndpointResolver(ResolverSettings{
				Hostname:        "example.com",
				Port:            51820,
				ResolveInterval: tt.resolveInterval,
				UseTTL:          tt.useTTL,
				MinInterval:     tt.minInterval,
			}, logger)

			resolver.mu.Lock()
			resolver.lastTTL = tt.lastTTL
			resolver.mu.Unlock()

			result := resolver.getNextResolveInterval()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEndpointResolver_resolveWithRetry(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("Skipping network-dependent test in short mode")
	}

	logger := &mockLogger{}

	tests := []struct {
		name        string
		hostname    string
		expectError bool
		timeout     time.Duration
	}{
		{
			name:        "successful resolution",
			hostname:    "cloudflare.com",
			expectError: false,
			timeout:     10 * time.Second,
		},
		{
			name:        "failed resolution",
			hostname:    "this-hostname-should-not-exist-12345.invalid",
			expectError: true,
			timeout:     10 * time.Second,
		},
		{
			name:        "context timeout",
			hostname:    "cloudflare.com",
			expectError: true,
			timeout:     1 * time.Nanosecond, // Very short timeout
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			resolver := NewEndpointResolver(ResolverSettings{
				Hostname: tt.hostname,
				Port:     443,
			}, logger)

			ctx, cancel := context.WithTimeout(context.Background(), tt.timeout)
			defer cancel()

			ips, err := resolver.resolveWithRetry(ctx)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, ips)
			}
		})
	}
}

// Mock logger for testing
type mockLogger struct {
	debugMessages []string
	infoMessages  []string
	errorMessages []string
}

func (m *mockLogger) Debug(s string) {
	m.debugMessages = append(m.debugMessages, s)
}

func (m *mockLogger) Debugf(format string, args ...interface{}) {
	// For simplicity, we'll just store the format string
	m.debugMessages = append(m.debugMessages, format)
}

func (m *mockLogger) Info(s string) {
	m.infoMessages = append(m.infoMessages, s)
}

func (m *mockLogger) Error(s string) {
	m.errorMessages = append(m.errorMessages, s)
}

func (m *mockLogger) Errorf(format string, args ...interface{}) {
	// For simplicity, we'll just store the format string
	m.errorMessages = append(m.errorMessages, format)
}
