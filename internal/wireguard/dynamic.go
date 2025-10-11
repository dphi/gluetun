package wireguard

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
)

// DynamicWireguard extends the standard Wireguard implementation with dynamic DNS resolution
// and connection health monitoring capabilities
type DynamicWireguard struct {
	*Wireguard // Embed existing Wireguard struct for backward compatibility
	resolver   *EndpointResolver
	monitor    *ConnectionMonitor
	settings   DynamicSettings

	// Reconnection state
	reconnectAttempts int
	lastReconnect     time.Time
	mu                sync.RWMutex
}

// DynamicSettings contains configuration for the DynamicWireguard manager
type DynamicSettings struct {
	Settings // Embed existing Settings

	// Dynamic DNS configuration
	Hostname            string
	ResolveInterval     time.Duration
	HealthCheckInterval time.Duration

	// Reconnection configuration
	MaxReconnectAttempts int
	ReconnectBackoff     time.Duration
	MaxReconnectBackoff  time.Duration
	BackoffFactor        float64

	// DNS resolver configuration
	DNSServer   string
	UseTTL      bool
	MinInterval time.Duration
}

// ReconnectionStrategy defines the exponential backoff strategy for reconnections
type ReconnectionStrategy struct {
	MaxAttempts    int           // Maximum number of reconnection attempts
	InitialBackoff time.Duration // Initial backoff duration
	MaxBackoff     time.Duration // Maximum backoff duration
	BackoffFactor  float64       // Backoff multiplier factor
}

// NewDynamicWireguard creates a new DynamicWireguard instance with hostname-based endpoint resolution
func NewDynamicWireguard(settings DynamicSettings, logger Logger, netLinker NetLinker) (*DynamicWireguard, error) {
	// Set default values for dynamic settings
	settings.setDefaults()

	// Validate dynamic settings
	if err := settings.validateDynamic(); err != nil {
		return nil, fmt.Errorf("invalid dynamic settings: %w", err)
	}

	// Create the base Wireguard instance
	baseWireguard, err := New(settings.Settings, netLinker, logger)
	if err != nil {
		return nil, fmt.Errorf("creating base Wireguard instance: %w", err)
	}

	// Create endpoint resolver
	resolverSettings := ResolverSettings{
		Hostname:        settings.Hostname,
		Port:            settings.Endpoint.Port(),
		ResolveInterval: settings.ResolveInterval,
		DNSServer:       settings.DNSServer,
		UseTTL:          settings.UseTTL,
		MinInterval:     settings.MinInterval,
	}
	resolver := NewEndpointResolver(resolverSettings, logger)

	// Create connection monitor
	monitorSettings := MonitorSettings{
		InterfaceName:       settings.InterfaceName,
		HealthInterval:      settings.HealthCheckInterval,
		HandshakeTimeout:    2 * time.Minute, // Default handshake timeout
		PersistentKeepalive: settings.PersistentKeepaliveInterval > 0,
	}

	// We'll create the monitor with a nil client initially and set it up during Run()
	monitor := NewConnectionMonitor(monitorSettings, nil, logger)

	return &DynamicWireguard{
		Wireguard: baseWireguard,
		resolver:  resolver,
		monitor:   monitor,
		settings:  settings,
	}, nil
}

// setDefaults sets default values for DynamicSettings
func (s *DynamicSettings) setDefaults() {
	// Call base settings defaults first
	s.Settings.SetDefaults()

	// Set dynamic-specific defaults
	if s.ResolveInterval == 0 {
		s.ResolveInterval = 5 * time.Minute // Default: 5 minutes
	}

	if s.HealthCheckInterval == 0 {
		s.HealthCheckInterval = 30 * time.Second // Default: 30 seconds
	}

	if s.MaxReconnectAttempts == 0 {
		s.MaxReconnectAttempts = 5 // Default: 5 attempts
	}

	if s.ReconnectBackoff == 0 {
		s.ReconnectBackoff = 1 * time.Second // Default: 1 second initial backoff
	}

	if s.MaxReconnectBackoff == 0 {
		s.MaxReconnectBackoff = 30 * time.Second // Default: 30 seconds max backoff
	}

	if s.BackoffFactor == 0 {
		s.BackoffFactor = 2.0 // Default: 2.0 factor
	}

	if s.MinInterval == 0 {
		s.MinInterval = 60 * time.Second // Default: 60 seconds minimum interval
	}

	if s.DNSServer == "" {
		s.DNSServer = "1.1.1.1" // Default: Cloudflare DNS
	}

	// Enable TTL usage by default
	s.UseTTL = true
}

// validateDynamic validates the dynamic-specific settings
func (s *DynamicSettings) validateDynamic() error {
	if s.Hostname == "" {
		return fmt.Errorf("hostname is required for dynamic WireGuard")
	}

	if s.ResolveInterval < 0 {
		return fmt.Errorf("resolve interval cannot be negative")
	}

	if s.HealthCheckInterval < 0 {
		return fmt.Errorf("health check interval cannot be negative")
	}

	if s.MaxReconnectAttempts < 0 {
		return fmt.Errorf("max reconnect attempts cannot be negative")
	}

	if s.ReconnectBackoff < 0 {
		return fmt.Errorf("reconnect backoff cannot be negative")
	}

	if s.MaxReconnectBackoff < s.ReconnectBackoff {
		return fmt.Errorf("max reconnect backoff cannot be less than initial backoff")
	}

	if s.BackoffFactor <= 0 {
		return fmt.Errorf("backoff factor must be positive")
	}

	if s.MinInterval < 0 {
		return fmt.Errorf("minimum interval cannot be negative")
	}

	return nil
}

// Run starts the dynamic WireGuard connection with DNS resolution and health monitoring
func (dw *DynamicWireguard) Run(ctx context.Context, waitError chan<- error, ready chan<- struct{}) {
	dw.logger.Info(fmt.Sprintf("Starting dynamic WireGuard: hostname=%s, resolve_interval=%v, health_interval=%v, max_reconnects=%d",
		dw.settings.Hostname, dw.settings.ResolveInterval, dw.settings.HealthCheckInterval, dw.settings.MaxReconnectAttempts))

	// Perform initial DNS resolution
	dw.logger.Debugf("Performing initial DNS resolution for hostname: %s", dw.settings.Hostname)
	startTime := time.Now()
	endpoint, err := dw.resolver.ResolveInitial(ctx)
	if err != nil {
		dw.logger.Errorf("Initial DNS resolution failed for hostname %s after %v: %v",
			dw.settings.Hostname, time.Since(startTime), err)
		waitError <- fmt.Errorf("initial DNS resolution failed: %w", err)
		return
	}

	resolutionTime := time.Since(startTime)
	dw.logger.Info(fmt.Sprintf("Initial DNS resolution successful: %s -> %s (resolved in %v)",
		dw.settings.Hostname, endpoint.String(), resolutionTime))

	// Update the endpoint in settings for the base Wireguard
	dw.settings.Settings.Endpoint = endpoint

	// Create wgctrl client for monitoring
	dw.logger.Debugf("Creating wgctrl client for connection monitoring")
	client, err := wgctrl.New()
	if err != nil {
		dw.logger.Errorf("Failed to create wgctrl client: %v", err)
		waitError <- fmt.Errorf("creating wgctrl client: %w", err)
		return
	}
	defer client.Close()

	// Update monitor with the client
	dw.monitor.client = client

	// Start the base Wireguard connection
	dw.logger.Info(fmt.Sprintf("Starting base WireGuard connection to %s", endpoint.String()))
	baseReady := make(chan struct{})
	baseError := make(chan error)

	go dw.Wireguard.Run(ctx, baseError, baseReady)

	// Wait for base connection to be ready or fail
	select {
	case <-baseReady:
		dw.logger.Info(fmt.Sprintf("Base WireGuard connection established successfully to %s", endpoint.String()))
	case err := <-baseError:
		dw.logger.Errorf("Base WireGuard connection failed to %s: %v", endpoint.String(), err)
		waitError <- fmt.Errorf("base WireGuard connection failed: %w", err)
		return
	case <-ctx.Done():
		dw.logger.Info("Dynamic WireGuard startup cancelled")
		waitError <- ctx.Err()
		return
	}

	// Signal that we're ready
	dw.logger.Info("Dynamic WireGuard is ready and operational")
	ready <- struct{}{}

	// Start monitoring and resolution in separate goroutines
	monitorCtx, monitorCancel := context.WithCancel(ctx)
	defer monitorCancel()

	var wg sync.WaitGroup

	// Start DNS resolution monitoring (if not disabled by persistent keepalive)
	wg.Add(1)
	go func() {
		defer wg.Done()
		dw.startDNSMonitoring(monitorCtx)
	}()

	// Start connection health monitoring
	wg.Add(1)
	go func() {
		defer wg.Done()
		dw.startHealthMonitoring(monitorCtx)
	}()

	// Wait for context cancellation or base connection error
	select {
	case <-ctx.Done():
		dw.logger.Info("Dynamic WireGuard stopping due to context cancellation")
		waitError <- ctx.Err()
	case err := <-baseError:
		dw.logger.Errorf("Base WireGuard connection error: %v", err)
		waitError <- err
	}

	// Cancel monitoring and wait for goroutines to finish
	dw.logger.Debug("Stopping monitoring goroutines")
	monitorCancel()
	wg.Wait()
	dw.logger.Info("Dynamic WireGuard stopped")
}

// startDNSMonitoring starts the DNS resolution monitoring loop
func (dw *DynamicWireguard) startDNSMonitoring(ctx context.Context) {
	// Check if periodic DNS resolution should be disabled due to persistent keepalive
	if dw.monitor.ShouldDisablePeriodicResolution() {
		dw.logger.Info(fmt.Sprintf("Periodic DNS resolution disabled: persistent keepalive is active for hostname %s", dw.settings.Hostname))
		return
	}

	dw.logger.Info(fmt.Sprintf("Starting DNS resolution monitoring: hostname=%s, interval=%v, min_interval=%v",
		dw.settings.Hostname, dw.settings.ResolveInterval, dw.settings.MinInterval))

	err := dw.resolver.StartMonitoring(ctx, dw.onEndpointChange)
	if err != nil && err != context.Canceled {
		dw.logger.Errorf("DNS resolution monitoring stopped with error for hostname %s: %v", dw.settings.Hostname, err)
	} else if err == context.Canceled {
		dw.logger.Debug("DNS resolution monitoring stopped due to context cancellation")
	} else {
		dw.logger.Info("DNS resolution monitoring stopped normally")
	}
}

// startHealthMonitoring starts the connection health monitoring loop
func (dw *DynamicWireguard) startHealthMonitoring(ctx context.Context) {
	dw.logger.Info(fmt.Sprintf("Starting connection health monitoring: interface=%s, interval=%v, handshake_timeout=%v",
		dw.settings.InterfaceName, dw.settings.HealthCheckInterval, 2*time.Minute))

	err := dw.monitor.StartMonitoring(ctx, dw.onConnectionUnhealthy)
	if err != nil && err != context.Canceled {
		dw.logger.Errorf("Connection health monitoring stopped with error for interface %s: %v", dw.settings.InterfaceName, err)
	} else if err == context.Canceled {
		dw.logger.Debug("Connection health monitoring stopped due to context cancellation")
	} else {
		dw.logger.Info("Connection health monitoring stopped normally")
	}
}

// onEndpointChange handles IP address changes detected by DNS resolution
func (dw *DynamicWireguard) onEndpointChange(newEndpoint netip.AddrPort) {
	oldEndpoint := dw.settings.Settings.Endpoint

	dw.logger.Info(fmt.Sprintf("DNS resolution detected IP address change: %s -> %s (hostname: %s)",
		oldEndpoint.String(), newEndpoint.String(), dw.settings.Hostname))

	// Trigger reconnection with the new endpoint
	dw.triggerReconnection(newEndpoint, "IP address change")
}

// onConnectionUnhealthy handles unhealthy connection detection
func (dw *DynamicWireguard) onConnectionUnhealthy() {
	lastHandshake, err := dw.monitor.GetLastHandshake()
	if err != nil {
		dw.logger.Errorf("Connection health issue detected: unable to get handshake info: %v", err)
	} else {
		timeSinceHandshake := time.Since(lastHandshake)
		dw.logger.Info(fmt.Sprintf("Connection health issue detected: last handshake %s ago, attempting hostname resolution and reconnection",
			timeSinceHandshake))
	}

	// Try to resolve the hostname again to get a fresh IP
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	dw.logger.Debugf("Resolving hostname %s for health recovery", dw.settings.Hostname)
	endpoint, err := dw.resolver.ResolveInitial(ctx)
	if err != nil {
		dw.logger.Errorf("Failed to resolve hostname %s during health recovery: %v", dw.settings.Hostname, err)
		return
	}

	dw.logger.Debugf("Health recovery DNS resolution successful: %s -> %s", dw.settings.Hostname, endpoint.String())

	// Trigger reconnection with the resolved endpoint
	dw.triggerReconnection(endpoint, "connection health issue")
}

// triggerReconnection initiates a reconnection with exponential backoff
func (dw *DynamicWireguard) triggerReconnection(newEndpoint netip.AddrPort, reason string) {
	dw.mu.Lock()
	defer dw.mu.Unlock()

	currentEndpoint := dw.settings.Settings.Endpoint

	// Check if we've exceeded maximum reconnection attempts
	if dw.reconnectAttempts >= dw.settings.MaxReconnectAttempts {
		dw.logger.Errorf("Reconnection failed: maximum attempts (%d) exceeded for endpoint %s -> %s (reason: %s)",
			dw.settings.MaxReconnectAttempts, currentEndpoint.String(), newEndpoint.String(), reason)
		return
	}

	// Calculate backoff delay
	backoffDelay := dw.calculateBackoffDelay()

	// Wait for backoff if this isn't the first attempt
	if dw.reconnectAttempts > 0 {
		dw.logger.Info(fmt.Sprintf("Reconnection backoff: waiting %v before attempt %d/%d (reason: %s, target: %s)",
			backoffDelay, dw.reconnectAttempts+1, dw.settings.MaxReconnectAttempts, reason, newEndpoint.String()))
		time.Sleep(backoffDelay)
	}

	dw.reconnectAttempts++
	dw.lastReconnect = time.Now()

	dw.logger.Info(fmt.Sprintf("Reconnection attempt %d/%d: %s -> %s (reason: %s, backoff: %v)",
		dw.reconnectAttempts, dw.settings.MaxReconnectAttempts,
		currentEndpoint.String(), newEndpoint.String(), reason, backoffDelay))

	// Perform the reconnection
	startTime := time.Now()
	if err := dw.performReconnection(newEndpoint); err != nil {
		duration := time.Since(startTime)
		dw.logger.Errorf("Reconnection attempt %d/%d failed after %v: %v (target: %s, reason: %s)",
			dw.reconnectAttempts, dw.settings.MaxReconnectAttempts, duration, err, newEndpoint.String(), reason)
		return
	}

	duration := time.Since(startTime)
	dw.logger.Info(fmt.Sprintf("Reconnection attempt %d/%d successful after %v: now connected to %s (reason: %s)",
		dw.reconnectAttempts, dw.settings.MaxReconnectAttempts, duration, newEndpoint.String(), reason))

	// Reset reconnection attempts on successful reconnection
	dw.reconnectAttempts = 0
}

// calculateBackoffDelay calculates the exponential backoff delay
func (dw *DynamicWireguard) calculateBackoffDelay() time.Duration {
	if dw.reconnectAttempts == 0 {
		return 0 // No delay for first attempt
	}

	// Calculate exponential backoff: initial * (factor ^ (attempts - 1))
	backoff := float64(dw.settings.ReconnectBackoff)
	for i := 1; i < dw.reconnectAttempts; i++ {
		backoff *= dw.settings.BackoffFactor
	}

	delay := time.Duration(backoff)

	// Cap at maximum backoff
	if delay > dw.settings.MaxReconnectBackoff {
		delay = dw.settings.MaxReconnectBackoff
	}

	return delay
}

// performReconnection performs the actual reconnection to a new endpoint
func (dw *DynamicWireguard) performReconnection(newEndpoint netip.AddrPort) error {
	oldEndpoint := dw.settings.Settings.Endpoint

	dw.logger.Debugf("Performing reconnection: updating endpoint from %s to %s", oldEndpoint.String(), newEndpoint.String())

	// Update the endpoint in our settings
	dw.settings.Settings.Endpoint = newEndpoint

	// Create a new wgctrl client for configuration
	dw.logger.Debugf("Creating wgctrl client for device reconfiguration")
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("creating wgctrl client for reconnection: %w", err)
	}
	defer client.Close()

	// Reconfigure the WireGuard device with the new endpoint
	dw.logger.Debugf("Reconfiguring WireGuard device %s with new endpoint %s", dw.settings.InterfaceName, newEndpoint.String())
	err = configureDevice(client, dw.settings.Settings)
	if err != nil {
		return fmt.Errorf("reconfiguring WireGuard device %s with endpoint %s: %w",
			dw.settings.InterfaceName, newEndpoint.String(), err)
	}

	dw.logger.Info(fmt.Sprintf("WireGuard device %s successfully reconfigured: %s -> %s",
		dw.settings.InterfaceName, oldEndpoint.String(), newEndpoint.String()))
	return nil
}

// GetReconnectionStats returns current reconnection statistics
func (dw *DynamicWireguard) GetReconnectionStats() (attempts int, lastReconnect time.Time) {
	dw.mu.RLock()
	defer dw.mu.RUnlock()
	return dw.reconnectAttempts, dw.lastReconnect
}

// GetCurrentEndpoint returns the currently configured endpoint
func (dw *DynamicWireguard) GetCurrentEndpoint() netip.AddrPort {
	return dw.resolver.GetCurrentEndpoint()
}

// ResetReconnectionAttempts resets the reconnection attempt counter
func (dw *DynamicWireguard) ResetReconnectionAttempts() {
	dw.mu.Lock()
	defer dw.mu.Unlock()
	dw.reconnectAttempts = 0
}
