package wireguard

import (
	"context"
	"fmt"
)

type Wireguard struct {
	logger   Logger
	settings Settings
	netlink  NetLinker
}

// WireguardInterface defines the common interface for both standard and dynamic WireGuard implementations
type WireguardInterface interface {
	Run(ctx context.Context, waitError chan<- error, ready chan<- struct{})
}

func New(settings Settings, netlink NetLinker,
	logger Logger,
) (w *Wireguard, err error) {
	settings.SetDefaults()
	if err := settings.Check(); err != nil {
		return nil, err
	}

	return &Wireguard{
		logger:   logger,
		settings: settings,
		netlink:  netlink,
	}, nil
}

// NewWireguardManager creates either a standard Wireguard or DynamicWireguard instance
// based on the configuration. If a hostname is configured, it returns a DynamicWireguard
// instance; otherwise, it returns a standard Wireguard instance for backward compatibility.
func NewWireguardManager(settings Settings, netlink NetLinker, logger Logger) (WireguardInterface, error) {
	// Check if hostname is configured for dynamic DNS
	if settings.EndpointHostname != "" {
		logger.Info(fmt.Sprintf("Creating dynamic WireGuard manager for hostname: %s", settings.EndpointHostname))

		// Create DynamicSettings from the base Settings
		dynamicSettings := DynamicSettings{
			Settings:            settings,
			Hostname:            settings.EndpointHostname,
			ResolveInterval:     settings.ResolveInterval,
			HealthCheckInterval: settings.HealthCheckInterval,
		}

		// Create and return DynamicWireguard instance
		return NewDynamicWireguard(dynamicSettings, logger, netlink)
	}

	// For IP-based configuration, use standard Wireguard for backward compatibility
	logger.Debug("Creating standard WireGuard instance for IP-based configuration")
	return New(settings, netlink, logger)
}
