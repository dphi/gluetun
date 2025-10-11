package wireguard

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/netlink"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDynamicWireguard_NewDynamicWireguard(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		settings    DynamicSettings
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid settings",
			settings: DynamicSettings{
				Settings: Settings{
					InterfaceName: "wg0",
					PrivateKey:    "cOFA+YD2Z4H6z7kBaHNmHiD2cjM+KeVj7RqfHBhXnHI=",
					PublicKey:     "VjVXceIjySdVRVXiMoeCpjM9NWjwNUN6nxW+CUsKk2s=",
					Addresses: []netip.Prefix{
						netip.MustParsePrefix("10.0.0.2/32"),
					},
					Endpoint: netip.AddrPortFrom(netip.MustParseAddr("192.168.1.1"), 51820), // Temporary endpoint
				},
				Hostname: "example.com",
			},
			expectError: false,
		},
		{
			name: "missing hostname",
			settings: DynamicSettings{
				Settings: Settings{
					InterfaceName: "wg0",
					PrivateKey:    "cOFA+YD2Z4H6z7kBaHNmHiD2cjM+KeVj7RqfHBhXnHI=",
					PublicKey:     "VjVXceIjySdVRVXiMoeCpjM9NWjwNUN6nxW+CUsKk2s=",
					Addresses: []netip.Prefix{
						netip.MustParsePrefix("10.0.0.2/32"),
					},
					Endpoint: netip.AddrPortFrom(netip.MustParseAddr("192.168.1.1"), 51820), // Temporary endpoint
				},
				Hostname: "",
			},
			expectError: true,
			errorMsg:    "hostname is required",
		},
		{
			name: "negative reconnect attempts",
			settings: DynamicSettings{
				Settings: Settings{
					InterfaceName: "wg0",
					PrivateKey:    "cOFA+YD2Z4H6z7kBaHNmHiD2cjM+KeVj7RqfHBhXnHI=",
					PublicKey:     "VjVXceIjySdVRVXiMoeCpjM9NWjwNUN6nxW+CUsKk2s=",
					Addresses: []netip.Prefix{
						netip.MustParsePrefix("10.0.0.2/32"),
					},
					Endpoint: netip.AddrPortFrom(netip.MustParseAddr("192.168.1.1"), 51820), // Temporary endpoint
				},
				Hostname:             "example.com",
				MaxReconnectAttempts: -1,
			},
			expectError: true,
			errorMsg:    "max reconnect attempts cannot be negative",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := &mockDynamicLogger{}
			netLinker := &mockNetLinker{}

			dw, err := NewDynamicWireguard(tt.settings, logger, netLinker)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, dw)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, dw)
				assert.Equal(t, tt.settings.Hostname, dw.settings.Hostname)

				// Check defaults were set
				assert.Equal(t, 5, dw.settings.MaxReconnectAttempts)
				assert.Equal(t, 1*time.Second, dw.settings.ReconnectBackoff)
				assert.Equal(t, 30*time.Second, dw.settings.MaxReconnectBackoff)
				assert.Equal(t, 2.0, dw.settings.BackoffFactor)
			}
		})
	}
}

func TestDynamicWireguard_CalculateBackoffDelay(t *testing.T) {
	t.Parallel()

	settings := DynamicSettings{
		Settings: Settings{
			InterfaceName: "wg0",
			PrivateKey:    "cOFA+YD2Z4H6z7kBaHNmHiD2cjM+KeVj7RqfHBhXnHI=",
			PublicKey:     "VjVXceIjySdVRVXiMoeCpjM9NWjwNUN6nxW+CUsKk2s=",
			Addresses: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.2/32"),
			},
			Endpoint: netip.AddrPortFrom(netip.MustParseAddr("192.168.1.1"), 51820), // Temporary endpoint
		},
		Hostname:            "example.com",
		ReconnectBackoff:    1 * time.Second,
		MaxReconnectBackoff: 30 * time.Second,
		BackoffFactor:       2.0,
	}

	logger := &mockDynamicLogger{}
	netLinker := &mockNetLinker{}

	dw, err := NewDynamicWireguard(settings, logger, netLinker)
	require.NoError(t, err)

	tests := []struct {
		attempts int
		expected time.Duration
	}{
		{0, 0 * time.Second},   // First attempt, no delay
		{1, 1 * time.Second},   // 1 * (2^0) = 1s
		{2, 2 * time.Second},   // 1 * (2^1) = 2s
		{3, 4 * time.Second},   // 1 * (2^2) = 4s
		{4, 8 * time.Second},   // 1 * (2^3) = 8s
		{5, 16 * time.Second},  // 1 * (2^4) = 16s
		{6, 30 * time.Second},  // 1 * (2^5) = 32s, capped at 30s
		{10, 30 * time.Second}, // Capped at max
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("attempt_%d", tt.attempts), func(t *testing.T) {
			dw.reconnectAttempts = tt.attempts
			delay := dw.calculateBackoffDelay()
			assert.Equal(t, tt.expected, delay)
		})
	}
}

func TestDynamicWireguard_EndpointChangeIntegration(t *testing.T) {
	t.Parallel()

	settings := DynamicSettings{
		Settings: Settings{
			InterfaceName: "wg0",
			PrivateKey:    "cOFA+YD2Z4H6z7kBaHNmHiD2cjM+KeVj7RqfHBhXnHI=",
			PublicKey:     "VjVXceIjySdVRVXiMoeCpjM9NWjwNUN6nxW+CUsKk2s=",
			Addresses: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.2/32"),
			},
			Endpoint: netip.AddrPortFrom(netip.MustParseAddr("192.168.1.1"), 51820),
		},
		Hostname: "example.com",
	}

	logger := &mockDynamicLogger{}
	netLinker := &mockNetLinker{}

	dw, err := NewDynamicWireguard(settings, logger, netLinker)
	require.NoError(t, err)

	// Test IP address change detection through the public interface
	oldEndpoint := dw.settings.Settings.Endpoint
	newIP := netip.MustParseAddr("192.168.1.2")
	newEndpoint := netip.AddrPortFrom(newIP, 51820)

	// Simulate IP change by calling the handler directly
	dw.onEndpointChange(newEndpoint)

	// Verify the endpoint was updated
	assert.Equal(t, newEndpoint, dw.settings.Settings.Endpoint)
	assert.NotEqual(t, oldEndpoint, dw.settings.Settings.Endpoint)

	// Check that logging occurred
	assert.True(t, logger.hasLoggedContaining("IP address change"))
}

func TestDynamicWireguard_HealthMonitoringIntegration(t *testing.T) {
	t.Parallel()

	settings := DynamicSettings{
		Settings: Settings{
			InterfaceName: "wg0",
			PrivateKey:    "cOFA+YD2Z4H6z7kBaHNmHiD2cjM+KeVj7RqfHBhXnHI=",
			PublicKey:     "VjVXceIjySdVRVXiMoeCpjM9NWjwNUN6nxW+CUsKk2s=",
			Addresses: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.2/32"),
			},
			Endpoint: netip.AddrPortFrom(netip.MustParseAddr("192.168.1.1"), 51820),
		},
		Hostname: "example.com",
	}

	logger := &mockDynamicLogger{}
	netLinker := &mockNetLinker{}

	dw, err := NewDynamicWireguard(settings, logger, netLinker)
	require.NoError(t, err)

	// Test that the DynamicWireguard was created successfully with health monitoring components
	assert.NotNil(t, dw.monitor)
	assert.Equal(t, "example.com", dw.settings.Hostname)
	assert.Equal(t, 30*time.Second, dw.settings.HealthCheckInterval)
}

func TestDynamicWireguard_ReconnectionLimits(t *testing.T) {
	t.Parallel()

	settings := DynamicSettings{
		Settings: Settings{
			InterfaceName: "wg0",
			PrivateKey:    "cOFA+YD2Z4H6z7kBaHNmHiD2cjM+KeVj7RqfHBhXnHI=",
			PublicKey:     "VjVXceIjySdVRVXiMoeCpjM9NWjwNUN6nxW+CUsKk2s=",
			Addresses: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.2/32"),
			},
			Endpoint: netip.AddrPortFrom(netip.MustParseAddr("192.168.1.1"), 51820),
		},
		Hostname:             "example.com",
		MaxReconnectAttempts: 3, // Low limit for testing
	}

	logger := &mockDynamicLogger{}
	netLinker := &mockNetLinker{}

	dw, err := NewDynamicWireguard(settings, logger, netLinker)
	require.NoError(t, err)

	// For this test, we'll test the reconnection limit logic without mocking
	// The reconnection will fail due to the mock wgctrl client not being available

	newEndpoint := netip.AddrPortFrom(netip.MustParseAddr("192.168.1.2"), 51820)

	// Trigger reconnections up to the limit
	for i := 0; i < 3; i++ {
		dw.triggerReconnection(newEndpoint, "test")
		assert.Equal(t, i+1, dw.reconnectAttempts)
	}

	// Try one more time - should be rejected due to limit
	initialAttempts := dw.reconnectAttempts
	dw.triggerReconnection(newEndpoint, "test")
	assert.Equal(t, initialAttempts, dw.reconnectAttempts) // Should not increment

	// Check that max attempts error was logged
	assert.True(t, logger.hasLoggedContaining("maximum attempts"))
}

// Mock implementations for testing

type mockDynamicLogger struct {
	logs []string
	mu   sync.RWMutex
}

func (m *mockDynamicLogger) Debug(s string) { m.log("DEBUG: " + s) }
func (m *mockDynamicLogger) Debugf(format string, args ...interface{}) {
	m.log(fmt.Sprintf("DEBUG: "+format, args...))
}
func (m *mockDynamicLogger) Info(s string) { m.log("INFO: " + s) }

func (m *mockDynamicLogger) Error(s string) { m.log("ERROR: " + s) }
func (m *mockDynamicLogger) Errorf(format string, args ...interface{}) {
	m.log(fmt.Sprintf("ERROR: "+format, args...))
}

func (m *mockDynamicLogger) log(msg string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logs = append(m.logs, msg)
}

func (m *mockDynamicLogger) hasLoggedContaining(substr string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, log := range m.logs {
		if strings.Contains(log, substr) {
			return true
		}
	}
	return false
}

type mockNetLinker struct{}

func (m *mockNetLinker) IsWireguardSupported() (bool, error)    { return true, nil }
func (m *mockNetLinker) LinkList() ([]netlink.Link, error)      { return nil, nil }
func (m *mockNetLinker) LinkAdd(link netlink.Link) (int, error) { return 1, nil }
func (m *mockNetLinker) LinkDel(link netlink.Link) error        { return nil }
func (m *mockNetLinker) LinkByName(name string) (netlink.Link, error) {
	return netlink.Link{Name: name, Index: 1}, nil
}
func (m *mockNetLinker) LinkSetUp(link netlink.Link) (int, error)               { return 1, nil }
func (m *mockNetLinker) LinkSetDown(link netlink.Link) error                    { return nil }
func (m *mockNetLinker) AddrReplace(link netlink.Link, addr netlink.Addr) error { return nil }
func (m *mockNetLinker) RouteList(family int) ([]netlink.Route, error)          { return nil, nil }
func (m *mockNetLinker) RouteAdd(route netlink.Route) error                     { return nil }
func (m *mockNetLinker) RuleAdd(rule netlink.Rule) error                        { return nil }
func (m *mockNetLinker) RuleDel(rule netlink.Rule) error                        { return nil }
