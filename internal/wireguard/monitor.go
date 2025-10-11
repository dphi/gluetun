package wireguard

import (
	"context"
	"fmt"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

//go:generate mockgen -destination=monitor_mock_test.go -package wireguard . WgctrlClient

// WgctrlClient interface for wgctrl.Client to enable mocking
type WgctrlClient interface {
	Device(name string) (*wgtypes.Device, error)
	ConfigureDevice(name string, cfg wgtypes.Config) error
	Close() error
}

// ConnectionMonitor monitors WireGuard connection health using handshake timestamps
type ConnectionMonitor struct {
	client              WgctrlClient
	interfaceName       string
	logger              Logger
	healthInterval      time.Duration
	handshakeTimeout    time.Duration
	lastHandshake       time.Time
	persistentKeepalive bool // Whether persistent keepalive is configured
}

// MonitorSettings contains configuration for the ConnectionMonitor
type MonitorSettings struct {
	InterfaceName       string
	HealthInterval      time.Duration // How often to check connection health
	HandshakeTimeout    time.Duration // How long without handshake before considering unhealthy
	PersistentKeepalive bool          // If true, affects health monitoring strategy
}

// NewConnectionMonitor creates a new ConnectionMonitor instance
func NewConnectionMonitor(settings MonitorSettings, client WgctrlClient, logger Logger) *ConnectionMonitor {
	// Set defaults
	if settings.HealthInterval == 0 {
		settings.HealthInterval = 30 * time.Second // Default: 30 seconds
	}
	if settings.HandshakeTimeout == 0 {
		settings.HandshakeTimeout = 2 * time.Minute // Default: 2 minutes
	}

	return &ConnectionMonitor{
		client:              client,
		interfaceName:       settings.InterfaceName,
		logger:              logger,
		healthInterval:      settings.HealthInterval,
		handshakeTimeout:    settings.HandshakeTimeout,
		persistentKeepalive: settings.PersistentKeepalive,
	}
}

// StartMonitoring begins monitoring the WireGuard connection health
// It calls onUnhealthy when an unhealthy connection is detected
func (m *ConnectionMonitor) StartMonitoring(ctx context.Context, onUnhealthy func()) error {
	m.logger.Info("Starting WireGuard connection health monitoring")

	ticker := time.NewTicker(m.healthInterval)
	defer ticker.Stop()

	// Initial health check
	healthy, err := m.IsHealthy(ctx)
	if err != nil {
		m.logger.Errorf("Initial health check failed: %s", err)
	} else if !healthy {
		m.logger.Info("Initial connection is unhealthy, triggering callback")
		onUnhealthy()
	}

	for {
		select {
		case <-ctx.Done():
			m.logger.Info("Stopping WireGuard connection health monitoring")
			return ctx.Err()
		case <-ticker.C:
			healthy, err := m.IsHealthy(ctx)
			if err != nil {
				m.logger.Errorf("Health check failed: %s", err)
				continue
			}

			if !healthy {
				m.logger.Info("Unhealthy WireGuard connection detected, triggering callback")
				onUnhealthy()
			}
		}
	}
}

// IsHealthy checks if the WireGuard connection is healthy based on handshake timestamps
func (m *ConnectionMonitor) IsHealthy(ctx context.Context) (bool, error) {
	device, err := m.client.Device(m.interfaceName)
	if err != nil {
		return false, fmt.Errorf("getting device %s: %w", m.interfaceName, err)
	}

	// Check if we have any peers
	if len(device.Peers) == 0 {
		m.logger.Debug("No peers found for WireGuard device")
		return false, nil
	}

	// Check the handshake timestamp of the first peer (assuming single peer setup)
	peer := device.Peers[0]

	// Update persistent keepalive status
	m.persistentKeepalive = peer.PersistentKeepaliveInterval > 0

	// If we've never had a handshake, consider it unhealthy
	if peer.LastHandshakeTime.IsZero() {
		m.logger.Debug("No handshake recorded yet")
		return false, nil
	}

	// Update our last handshake time
	m.lastHandshake = peer.LastHandshakeTime

	// Check if the handshake is recent enough
	timeSinceHandshake := time.Since(peer.LastHandshakeTime)

	// Adjust timeout based on persistent keepalive configuration
	effectiveTimeout := m.handshakeTimeout
	if m.persistentKeepalive {
		// When persistent keepalive is active, we can be more lenient with handshake timeout
		// since keepalive packets help maintain the connection
		keepaliveInterval := peer.PersistentKeepaliveInterval
		if keepaliveInterval > 0 {
			// Allow for a few missed keepalive intervals before considering unhealthy
			effectiveTimeout = keepaliveInterval * 3
			if effectiveTimeout > m.handshakeTimeout {
				effectiveTimeout = m.handshakeTimeout
			}
		}
	}

	healthy := timeSinceHandshake <= effectiveTimeout

	if healthy {
		m.logger.Debugf("Connection healthy: last handshake %s ago (timeout: %s, keepalive: %v)",
			timeSinceHandshake, effectiveTimeout, m.persistentKeepalive)
	} else {
		m.logger.Debugf("Connection unhealthy: last handshake %s ago (timeout: %s, keepalive: %v)",
			timeSinceHandshake, effectiveTimeout, m.persistentKeepalive)
	}

	return healthy, nil
}

// GetLastHandshake returns the timestamp of the last recorded handshake
func (m *ConnectionMonitor) GetLastHandshake() (time.Time, error) {
	device, err := m.client.Device(m.interfaceName)
	if err != nil {
		return time.Time{}, fmt.Errorf("getting device %s: %w", m.interfaceName, err)
	}

	if len(device.Peers) == 0 {
		return time.Time{}, fmt.Errorf("no peers found for device %s", m.interfaceName)
	}

	return device.Peers[0].LastHandshakeTime, nil
}

// HasPersistentKeepalive checks if persistent keepalive is configured for the connection
func (m *ConnectionMonitor) HasPersistentKeepalive() (bool, error) {
	device, err := m.client.Device(m.interfaceName)
	if err != nil {
		return false, fmt.Errorf("getting device %s: %w", m.interfaceName, err)
	}

	if len(device.Peers) == 0 {
		return false, nil
	}

	peer := device.Peers[0]
	return peer.PersistentKeepaliveInterval > 0, nil
}

// UpdatePersistentKeepaliveStatus detects and updates the persistent keepalive status
func (m *ConnectionMonitor) UpdatePersistentKeepaliveStatus() error {
	hasKeepalive, err := m.HasPersistentKeepalive()
	if err != nil {
		return fmt.Errorf("checking persistent keepalive status: %w", err)
	}

	if hasKeepalive != m.persistentKeepalive {
		m.persistentKeepalive = hasKeepalive
		if hasKeepalive {
			m.logger.Info("Persistent keepalive detected - will use as part of health monitoring strategy")
		} else {
			m.logger.Info("Persistent keepalive not configured - using standard health monitoring")
		}
	}

	return nil
}

// ShouldDisablePeriodicResolution returns true if periodic DNS resolution should be disabled
// This happens when persistent keepalive is active, as per requirement 4.4
func (m *ConnectionMonitor) ShouldDisablePeriodicResolution() bool {
	return m.persistentKeepalive
}
