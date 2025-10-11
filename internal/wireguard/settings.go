package wireguard

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Settings struct {
	// Interface name for the Wireguard interface.
	// It defaults to wg0 if unset.
	InterfaceName string
	// Private key in base 64 format
	PrivateKey string
	// Public key in base 64 format
	PublicKey string
	// Pre shared key in base 64 format
	PreSharedKey string
	// Wireguard server endpoint to connect to.
	Endpoint netip.AddrPort
	// EndpointHostname is the server endpoint hostname for dynamic DNS scenarios.
	// It is mutually exclusive with a static IP endpoint.
	EndpointHostname string
	// ResolveInterval is the interval for re-resolving the hostname.
	// It defaults to DNS record TTL with a minimum of 60 seconds.
	ResolveInterval time.Duration
	// HealthCheckInterval is the interval for checking connection health.
	// It defaults to 30 seconds.
	HealthCheckInterval time.Duration
	// Addresses assigned to the client.
	// Note IPv6 addresses are ignored if IPv6 is not supported.
	Addresses []netip.Prefix
	// AllowedIPs is the IP networks to be routed through
	// the Wireguard interface.
	// Note IPv6 addresses are ignored if IPv6 is not supported.
	AllowedIPs []netip.Prefix
	// PersistentKeepaliveInterval defines the keep alive interval, if not zero.
	PersistentKeepaliveInterval time.Duration
	// FirewallMark to be used in routing tables and IP rules.
	// It defaults to 51820 if left to 0.
	FirewallMark uint32
	// Maximum Transmission Unit (MTU) setting for the network interface.
	// It defaults to device.DefaultMTU from wireguard-go which is 1420
	MTU uint16
	// RulePriority is the priority for the rule created with the
	// FirewallMark.
	RulePriority int
	// IPv6 can bet set to true if IPv6 should be handled.
	// It defaults to false if left unset.
	IPv6 *bool
	// Implementation is the implementation to use.
	// It can be auto, kernelspace or userspace, and defaults to auto.
	Implementation string
}

func (s *Settings) SetDefaults() {
	if s.InterfaceName == "" {
		const defaultInterfaceName = "wg0"
		s.InterfaceName = defaultInterfaceName
	}

	if s.Endpoint.IsValid() && s.Endpoint.Port() == 0 {
		const defaultPort = 51820
		s.Endpoint = netip.AddrPortFrom(s.Endpoint.Addr(), defaultPort)
	}

	// Set default intervals for hostname-based endpoints
	if s.EndpointHostname != "" {
		// Set default resolve interval to DNS TTL with 60-second minimum
		// The actual TTL-based resolution will be handled by the resolver
		if s.ResolveInterval == 0 {
			const defaultResolveInterval = 60 * time.Second // Minimum 60 seconds as per requirements
			s.ResolveInterval = defaultResolveInterval
		} else if s.ResolveInterval < 60*time.Second {
			// Enforce minimum 60-second interval even for custom values
			s.ResolveInterval = 60 * time.Second
		}

		// Set default health check interval to 30 seconds
		if s.HealthCheckInterval == 0 {
			const defaultHealthCheckInterval = 30 * time.Second // Default 30 seconds as per requirements
			s.HealthCheckInterval = defaultHealthCheckInterval
		} else if s.HealthCheckInterval < time.Second {
			// Enforce minimum 1-second interval for health checks
			s.HealthCheckInterval = time.Second
		}
	}

	if s.FirewallMark == 0 {
		const defaultFirewallMark = 51820
		s.FirewallMark = defaultFirewallMark
	}

	if s.MTU == 0 {
		s.MTU = device.DefaultMTU
	}

	if s.IPv6 == nil {
		ipv6 := false // this should be injected from host
		s.IPv6 = &ipv6
	}

	if len(s.AllowedIPs) == 0 {
		s.AllowedIPs = append(s.AllowedIPs, allIPv4())
		if *s.IPv6 {
			s.AllowedIPs = append(s.AllowedIPs, allIPv6())
		}
	}

	if s.Implementation == "" {
		const defaultImplementation = "auto"
		s.Implementation = defaultImplementation
	}
}

var (
	ErrInterfaceNameInvalid       = errors.New("invalid interface name")
	ErrPrivateKeyMissing          = errors.New("private key is missing")
	ErrPrivateKeyInvalid          = errors.New("cannot parse private key")
	ErrPublicKeyMissing           = errors.New("public key is missing")
	ErrPublicKeyInvalid           = errors.New("cannot parse public key")
	ErrPreSharedKeyInvalid        = errors.New("cannot parse pre-shared key")
	ErrEndpointAddrMissing        = errors.New("endpoint address is missing")
	ErrEndpointPortMissing        = errors.New("endpoint port is missing")
	ErrEndpointMutuallyExclusive  = errors.New("endpoint IP and hostname are mutually exclusive")
	ErrEndpointRequired           = errors.New("either endpoint IP or hostname is required")
	ErrEndpointHostnameInvalid    = errors.New("endpoint hostname is not valid")
	ErrEndpointResolutionFailed   = errors.New("endpoint hostname resolution failed")
	ErrAddressMissing             = errors.New("interface address is missing")
	ErrAddressNotValid            = errors.New("interface address is not valid")
	ErrAllowedIPsMissing          = errors.New("allowed IPs are missing")
	ErrAllowedIPNotValid          = errors.New("allowed IP is not valid")
	ErrAllowedIPv6NotSupported    = errors.New("allowed IPv6 address not supported")
	ErrKeepaliveIsNegative        = errors.New("keep alive interval is negative")
	ErrFirewallMarkMissing        = errors.New("firewall mark is missing")
	ErrMTUMissing                 = errors.New("MTU is missing")
	ErrImplementationInvalid      = errors.New("invalid implementation")
	ErrResolveIntervalInvalid     = errors.New("resolve interval is invalid")
	ErrHealthCheckIntervalInvalid = errors.New("health check interval is invalid")
)

var (
	interfaceNameRegexp = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
	// hostnameRegex validates DNS hostname format according to RFC 1123
	hostnameRegex = regexp.MustCompile(`^([a-zA-Z0-9]|[a-zA-Z0-9_][a-zA-Z0-9\-_]{0,61}[a-zA-Z0-9_])(\.([a-zA-Z0-9]|[a-zA-Z0-9_][a-zA-Z0-9\-_]{0,61}[a-zA-Z0-9]))*$`) //nolint:lll
)

func (s *Settings) Check() (err error) {
	if !interfaceNameRegexp.MatchString(s.InterfaceName) {
		return fmt.Errorf("%w: %s", ErrInterfaceNameInvalid, s.InterfaceName)
	}

	if s.PrivateKey == "" {
		return fmt.Errorf("%w", ErrPrivateKeyMissing)
	} else if _, err := wgtypes.ParseKey(s.PrivateKey); err != nil {
		return fmt.Errorf("%w", ErrPrivateKeyInvalid)
	}

	if s.PublicKey == "" {
		return fmt.Errorf("%w", ErrPublicKeyMissing)
	} else if _, err := wgtypes.ParseKey(s.PublicKey); err != nil {
		return fmt.Errorf("%w: %s", ErrPublicKeyInvalid, s.PublicKey)
	}

	if s.PreSharedKey != "" {
		if _, err := wgtypes.ParseKey(s.PreSharedKey); err != nil {
			return fmt.Errorf("%w", ErrPreSharedKeyInvalid)
		}
	}

	// Validate endpoint configuration (IP vs Hostname mutual exclusivity)
	if err := s.validateEndpoint(); err != nil {
		return err
	}

	if len(s.Addresses) == 0 {
		return fmt.Errorf("%w", ErrAddressMissing)
	}
	for i, addr := range s.Addresses {
		if !addr.IsValid() {
			return fmt.Errorf("%w: for address %d of %d",
				ErrAddressNotValid, i+1, len(s.Addresses))
		}
	}

	if len(s.AllowedIPs) == 0 {
		return fmt.Errorf("%w", ErrAllowedIPsMissing)
	}
	for i, allowedIP := range s.AllowedIPs {
		switch {
		case !allowedIP.IsValid():
			return fmt.Errorf("%w: for allowed IP %d of %d",
				ErrAllowedIPNotValid, i+1, len(s.AllowedIPs))
		case allowedIP.Addr().Is6() && !*s.IPv6:
			return fmt.Errorf("%w: for allowed IP %s",
				ErrAllowedIPv6NotSupported, allowedIP)
		}
	}

	if s.PersistentKeepaliveInterval < 0 {
		return fmt.Errorf("%w: %s", ErrKeepaliveIsNegative,
			s.PersistentKeepaliveInterval)
	}

	if s.FirewallMark == 0 {
		return fmt.Errorf("%w", ErrFirewallMarkMissing)
	}

	if s.MTU == 0 {
		return fmt.Errorf("%w", ErrMTUMissing)
	}

	switch s.Implementation {
	case "auto", "kernelspace", "userspace":
	default:
		return fmt.Errorf("%w: %s", ErrImplementationInvalid, s.Implementation)
	}

	return nil
}

func (s Settings) String() string {
	lines := s.ToLines(ToLinesSettings{})
	return strings.Join(lines, "\n")
}

type ToLinesSettings struct {
	// Indent defaults to 4 spaces "    ".
	Indent *string
	// FieldPrefix defaults to "├── ".
	FieldPrefix *string
	// LastFieldPrefix defaults to "└── ".
	LastFieldPrefix *string
}

func (settings *ToLinesSettings) setDefaults() {
	toStringPtr := func(s string) *string { return &s }
	if settings.Indent == nil {
		settings.Indent = toStringPtr("    ")
	}
	if settings.FieldPrefix == nil {
		settings.FieldPrefix = toStringPtr("├── ")
	}
	if settings.LastFieldPrefix == nil {
		settings.LastFieldPrefix = toStringPtr("└── ")
	}
}

// ToLines serializes the settings to a slice of strings for display.
func (s Settings) ToLines(settings ToLinesSettings) (lines []string) {
	settings.setDefaults()

	indent := *settings.Indent
	fieldPrefix := *settings.FieldPrefix
	lastFieldPrefix := *settings.LastFieldPrefix

	lines = append(lines, fieldPrefix+"Interface name: "+s.InterfaceName)
	const (
		set    = "set"
		notSet = "not set"
	)

	isSet := notSet
	if s.PrivateKey != "" {
		isSet = set
	}
	lines = append(lines, fieldPrefix+"Private key: "+isSet)

	if s.PublicKey != "" {
		lines = append(lines, fieldPrefix+"PublicKey: "+s.PublicKey)
	}

	isSet = notSet
	if s.PreSharedKey != "" {
		isSet = set
	}
	lines = append(lines, fieldPrefix+"Pre shared key: "+isSet)

	endpointStr := notSet
	if s.Endpoint.Addr().IsValid() {
		endpointStr = s.Endpoint.String()
	}
	lines = append(lines, fieldPrefix+"Endpoint: "+endpointStr)

	ipv6Status := "disabled"
	if *s.IPv6 {
		ipv6Status = "enabled"
	}
	lines = append(lines, fieldPrefix+"IPv6: "+ipv6Status)

	if s.FirewallMark != 0 {
		lines = append(lines, fieldPrefix+"Firewall mark: "+fmt.Sprint(s.FirewallMark))
	}

	if s.MTU != 0 {
		lines = append(lines, fieldPrefix+"MTU: "+fmt.Sprint(s.MTU))
	}

	if s.RulePriority != 0 {
		lines = append(lines, fieldPrefix+"Rule priority: "+fmt.Sprint(s.RulePriority))
	}

	if s.Implementation != "auto" {
		lines = append(lines, fieldPrefix+"Implementation: "+s.Implementation)
	}

	if len(s.Addresses) == 0 {
		lines = append(lines, lastFieldPrefix+"Addresses: "+notSet)
	} else {
		lines = append(lines, lastFieldPrefix+"Addresses:")
		for i, address := range s.Addresses {
			prefix := fieldPrefix
			if i == len(s.Addresses)-1 {
				prefix = lastFieldPrefix
			}
			lines = append(lines, indent+prefix+address.String())
		}
	}

	if len(s.AllowedIPs) > 0 {
		lines = append(lines, fieldPrefix+"Allowed IPs:")
		for i, allowedIP := range s.AllowedIPs {
			prefix := fieldPrefix
			if i == len(s.AllowedIPs)-1 {
				prefix = lastFieldPrefix
			}
			lines = append(lines, indent+prefix+allowedIP.String())
		}
	}

	if s.PersistentKeepaliveInterval > 0 {
		lines = append(lines, fieldPrefix+"Persistent keep alive interval: "+
			s.PersistentKeepaliveInterval.String())
	}

	return lines
}

// validateEndpoint validates endpoint configuration ensuring mutual exclusivity
// between IP and hostname, and validates hostname format when provided.
func (s *Settings) validateEndpoint() error {
	hasIP := s.Endpoint.Addr().IsValid() && !s.Endpoint.Addr().IsUnspecified()
	hasHostname := s.EndpointHostname != ""

	// Check mutual exclusivity
	if hasIP && hasHostname {
		return fmt.Errorf("%w", ErrEndpointMutuallyExclusive)
	}

	// At least one endpoint configuration is required
	if !hasIP && !hasHostname {
		return fmt.Errorf("%w", ErrEndpointRequired)
	}

	// Validate hostname format if provided
	if hasHostname {
		if !hostnameRegex.MatchString(s.EndpointHostname) {
			return fmt.Errorf("%w: %s", ErrEndpointHostnameInvalid, s.EndpointHostname)
		}

		// Validate intervals for hostname-based endpoints
		if s.ResolveInterval < 0 {
			return fmt.Errorf("%w: resolve interval cannot be negative", ErrResolveIntervalInvalid)
		}
		if s.ResolveInterval > 0 && s.ResolveInterval < 60*time.Second {
			return fmt.Errorf("%w: resolve interval must be at least 60 seconds", ErrResolveIntervalInvalid)
		}
		if s.HealthCheckInterval < 0 {
			return fmt.Errorf("%w: health check interval cannot be negative", ErrHealthCheckIntervalInvalid)
		}
		if s.HealthCheckInterval > 0 && s.HealthCheckInterval < time.Second {
			return fmt.Errorf("%w: health check interval must be at least 1 second", ErrHealthCheckIntervalInvalid)
		}
	}

	// For IP-based endpoints, validate the existing endpoint requirements
	if hasIP {
		if s.Endpoint.Port() == 0 {
			return fmt.Errorf("%w", ErrEndpointPortMissing)
		}
	}

	return nil
}

// resolveHostnameEndpoint performs initial hostname resolution for hostname-based endpoints.
// This method should be called during initialization to validate that the hostname can be resolved.
func (s *Settings) resolveHostnameEndpoint(ctx context.Context) error {
	if s.EndpointHostname == "" {
		return nil // No hostname to resolve
	}

	// Create a temporary resolver for initial validation
	resolverSettings := ResolverSettings{
		Hostname:        s.EndpointHostname,
		Port:            51820, // Default WireGuard port for validation
		ResolveInterval: s.ResolveInterval,
		UseTTL:          true,
		MinInterval:     60 * time.Second,
	}

	// Use a no-op logger for validation
	logger := &noOpLogger{}
	resolver := NewEndpointResolver(resolverSettings, logger)

	// Attempt initial resolution to validate the hostname
	endpoint, err := resolver.ResolveInitial(ctx)
	if err != nil {
		return fmt.Errorf("%w: %s: %s", ErrEndpointResolutionFailed, s.EndpointHostname, err)
	}

	// Update the endpoint with the resolved IP for initial configuration
	// The port will be set correctly later based on the actual configuration
	s.Endpoint = endpoint

	return nil
}

// noOpLogger is a minimal logger implementation for validation purposes
type noOpLogger struct{}

func (l *noOpLogger) Debug(msg string)                          {}
func (l *noOpLogger) Debugf(format string, args ...interface{}) {}
func (l *noOpLogger) Info(msg string)                           {}
func (l *noOpLogger) Infof(format string, args ...interface{})  {}
func (l *noOpLogger) Warn(msg string)                           {}
func (l *noOpLogger) Warnf(format string, args ...interface{})  {}
func (l *noOpLogger) Error(msg string)                          {}
func (l *noOpLogger) Errorf(format string, args ...interface{}) {}

// GetEffectiveResolveInterval returns the effective resolve interval,
// taking into account DNS TTL with the 60-second minimum requirement.
// This method can be used by the resolver to determine the actual interval to use.
func (s *Settings) GetEffectiveResolveInterval(dnsTTL time.Duration) time.Duration {
	if s.EndpointHostname == "" {
		return 0 // Not applicable for IP-based endpoints
	}

	// If DNS TTL is available and valid, use it with minimum enforcement
	if dnsTTL > 0 {
		const minInterval = 60 * time.Second
		if dnsTTL < minInterval {
			return minInterval
		}
		return dnsTTL
	}

	// Fallback to configured interval
	return s.ResolveInterval
}

// GetEffectiveHealthCheckInterval returns the effective health check interval.
func (s *Settings) GetEffectiveHealthCheckInterval() time.Duration {
	if s.EndpointHostname == "" {
		return 0 // Not applicable for IP-based endpoints
	}

	return s.HealthCheckInterval
}

// IsHostnameBased returns true if this configuration uses hostname-based endpoints.
func (s *Settings) IsHostnameBased() bool {
	return s.EndpointHostname != ""
}
