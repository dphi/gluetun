package wireguard

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/qdm12/gluetun/internal/updater/resolver"
)

// EndpointResolver handles DNS resolution for WireGuard endpoints
type EndpointResolver struct {
	resolver        *resolver.Repeat
	logger          Logger
	hostname        string
	port            uint16
	currentIP       netip.Addr
	resolveInterval time.Duration
	minInterval     time.Duration
	useTTL          bool
	dnsServer       string
	lastTTL         time.Duration

	// Mutex to protect concurrent access to currentIP and lastTTL
	mu sync.RWMutex
}

// ResolverSettings contains configuration for the EndpointResolver
type ResolverSettings struct {
	Hostname        string
	Port            uint16
	ResolveInterval time.Duration
	DNSServer       string        // Optional custom DNS server
	UseTTL          bool          // Use DNS record TTL for resolution interval
	MinInterval     time.Duration // Minimum resolution interval (default: 60s)
}

// NewEndpointResolver creates a new EndpointResolver instance
func NewEndpointResolver(settings ResolverSettings, logger Logger) *EndpointResolver {
	// Set default minimum interval if not specified
	if settings.MinInterval == 0 {
		settings.MinInterval = 60 * time.Second
	}

	// Use system resolver if no custom DNS server specified
	dnsServer := "1.1.1.1" // Default to Cloudflare DNS
	if settings.DNSServer != "" {
		dnsServer = settings.DNSServer
	}

	return &EndpointResolver{
		resolver:        resolver.NewRepeat(dnsServer),
		logger:          logger,
		hostname:        settings.Hostname,
		port:            settings.Port,
		resolveInterval: settings.ResolveInterval,
		minInterval:     settings.MinInterval,
		useTTL:          settings.UseTTL,
		dnsServer:       dnsServer,
	}
}

// ResolveInitial performs the initial DNS resolution with retry logic
func (r *EndpointResolver) ResolveInitial(ctx context.Context) (netip.AddrPort, error) {
	r.logger.Debugf("Starting initial DNS resolution for hostname: %s", r.hostname)

	ips, err := r.resolveWithRetry(ctx)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("initial DNS resolution failed for %s: %w", r.hostname, err)
	}

	if len(ips) == 0 {
		return netip.AddrPort{}, fmt.Errorf("no IP addresses resolved for hostname: %s", r.hostname)
	}

	// Prefer IPv6 first, then IPv4 as per requirements
	selectedIP := r.selectPreferredIP(ips)

	r.mu.Lock()
	r.currentIP = selectedIP
	r.mu.Unlock()

	endpoint := netip.AddrPortFrom(selectedIP, r.port)
	r.logger.Debugf("Initial DNS resolution successful: %s -> %s", r.hostname, endpoint.String())

	return endpoint, nil
}

// resolveWithRetry implements exponential backoff retry logic for DNS resolution
func (r *EndpointResolver) resolveWithRetry(ctx context.Context) ([]netip.Addr, error) {
	backoffDurations := []time.Duration{
		1 * time.Second,
		2 * time.Second,
		4 * time.Second,
		8 * time.Second,
		30 * time.Second, // Max backoff
	}

	var lastErr error

	for i, backoff := range backoffDurations {
		ips, err := r.lookupIPs(ctx)
		if err == nil {
			if i > 0 {
				r.logger.Debugf("DNS resolution succeeded after %d retries for %s", i, r.hostname)
			}
			return ips, nil
		}

		lastErr = err
		r.logger.Debugf("DNS resolution attempt %d failed for %s: %v", i+1, r.hostname, err)

		// Don't wait after the last attempt
		if i == len(backoffDurations)-1 {
			break
		}

		// Wait with backoff, but respect context cancellation
		select {
		case <-time.After(backoff):
			continue
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	return nil, fmt.Errorf("DNS resolution failed after %d attempts: %w", len(backoffDurations), lastErr)
}

// lookupIPs performs a single DNS lookup and returns all resolved IP addresses
func (r *EndpointResolver) lookupIPs(ctx context.Context) ([]netip.Addr, error) {
	// Use a custom resolver to get more control over the resolution process
	resolver := &net.Resolver{
		PreferGo: true,
	}

	addresses, err := resolver.LookupIPAddr(ctx, r.hostname)
	if err != nil {
		return nil, err
	}

	if len(addresses) == 0 {
		return nil, fmt.Errorf("no IP addresses found for hostname: %s", r.hostname)
	}

	ips := make([]netip.Addr, 0, len(addresses))
	for _, addr := range addresses {
		ip, ok := netip.AddrFromSlice(addr.IP)
		if !ok {
			r.logger.Debugf("Skipping invalid IP address from DNS response: %v", addr.IP)
			continue
		}
		ips = append(ips, ip)
	}

	return ips, nil
}

// selectPreferredIP selects the preferred IP from a list, prioritizing IPv6 first, then IPv4
func (r *EndpointResolver) selectPreferredIP(ips []netip.Addr) netip.Addr {
	if len(ips) == 0 {
		return netip.Addr{}
	}

	// Separate IPv6 and IPv4 addresses
	var ipv6Addrs, ipv4Addrs []netip.Addr

	for _, ip := range ips {
		if ip.Is6() {
			ipv6Addrs = append(ipv6Addrs, ip)
		} else if ip.Is4() {
			ipv4Addrs = append(ipv4Addrs, ip)
		}
	}

	// Sort addresses for consistent selection
	sort.Slice(ipv6Addrs, func(i, j int) bool {
		return ipv6Addrs[i].Compare(ipv6Addrs[j]) < 0
	})
	sort.Slice(ipv4Addrs, func(i, j int) bool {
		return ipv4Addrs[i].Compare(ipv4Addrs[j]) < 0
	})

	// Prefer IPv6 first, then IPv4
	if len(ipv6Addrs) > 0 {
		r.logger.Debugf("Selected IPv6 address: %s (from %d IPv6 and %d IPv4 addresses)",
			ipv6Addrs[0].String(), len(ipv6Addrs), len(ipv4Addrs))
		return ipv6Addrs[0]
	}

	if len(ipv4Addrs) > 0 {
		r.logger.Debugf("Selected IPv4 address: %s (from %d IPv4 addresses)",
			ipv4Addrs[0].String(), len(ipv4Addrs))
		return ipv4Addrs[0]
	}

	// Fallback to first IP if no IPv4/IPv6 classification worked
	r.logger.Debugf("Selected fallback address: %s", ips[0].String())
	return ips[0]
}

// GetCurrentEndpoint returns the current resolved endpoint
func (r *EndpointResolver) GetCurrentEndpoint() netip.AddrPort {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return netip.AddrPortFrom(r.currentIP, r.port)
}

// ResolveMultipleIPs resolves the hostname and returns all IP addresses, trying IPv6 first, then IPv4
func (r *EndpointResolver) ResolveMultipleIPs(ctx context.Context) ([]netip.Addr, error) {
	ips, err := r.lookupIPs(ctx)
	if err != nil {
		return nil, err
	}

	// Separate and sort IPv6 and IPv4 addresses
	var ipv6Addrs, ipv4Addrs []netip.Addr

	for _, ip := range ips {
		if ip.Is6() {
			ipv6Addrs = append(ipv6Addrs, ip)
		} else if ip.Is4() {
			ipv4Addrs = append(ipv4Addrs, ip)
		}
	}

	// Sort addresses for consistent ordering
	sort.Slice(ipv6Addrs, func(i, j int) bool {
		return ipv6Addrs[i].Compare(ipv6Addrs[j]) < 0
	})
	sort.Slice(ipv4Addrs, func(i, j int) bool {
		return ipv4Addrs[i].Compare(ipv4Addrs[j]) < 0
	})

	// Return IPv6 addresses first, then IPv4 addresses
	result := make([]netip.Addr, 0, len(ips))
	result = append(result, ipv6Addrs...)
	result = append(result, ipv4Addrs...)

	return result, nil
}

// StartMonitoring starts periodic DNS resolution monitoring with IP change detection
func (r *EndpointResolver) StartMonitoring(ctx context.Context, onChange func(netip.AddrPort)) error {
	r.logger.Debug("Starting DNS resolution monitoring")

	ticker := time.NewTicker(r.getNextResolveInterval())
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			r.logger.Debug("DNS resolution monitoring stopped due to context cancellation")
			return ctx.Err()
		case <-ticker.C:
			if err := r.checkForIPChange(ctx, onChange); err != nil {
				r.logger.Errorf("Error during periodic DNS resolution: %v", err)
			}

			// Update ticker with new interval (potentially based on TTL)
			ticker.Reset(r.getNextResolveInterval())
		}
	}
}

// checkForIPChange performs DNS resolution and checks if the IP has changed
func (r *EndpointResolver) checkForIPChange(ctx context.Context, onChange func(netip.AddrPort)) error {
	r.logger.Debugf("Checking for IP address changes for hostname: %s", r.hostname)

	// Resolve with TTL extraction
	ips, ttl, err := r.resolveWithTTL(ctx)
	if err != nil {
		r.logger.Errorf("DNS resolution failed during monitoring: %v", err)
		return err
	}

	if len(ips) == 0 {
		r.logger.Errorf("No IP addresses resolved for hostname: %s", r.hostname)
		return fmt.Errorf("no IP addresses resolved for hostname: %s", r.hostname)
	}

	newIP := r.selectPreferredIP(ips)

	r.mu.Lock()
	oldIP := r.currentIP
	hasChanged := !oldIP.IsValid() || oldIP != newIP

	if hasChanged {
		r.currentIP = newIP
	}

	if ttl > 0 {
		r.lastTTL = ttl
	}
	r.mu.Unlock()

	if hasChanged {
		newEndpoint := netip.AddrPortFrom(newIP, r.port)
		r.logger.Debugf("IP address changed: %s -> %s", oldIP.String(), newIP.String())

		if onChange != nil {
			onChange(newEndpoint)
		}
	} else {
		r.logger.Debugf("IP address unchanged: %s", newIP.String())
	}

	return nil
}

// resolveWithTTL performs DNS resolution and extracts TTL information
func (r *EndpointResolver) resolveWithTTL(ctx context.Context) ([]netip.Addr, time.Duration, error) {
	// First try to get TTL using raw DNS query
	if r.useTTL {
		ips, ttl, err := r.queryDNSWithTTL(ctx)
		if err == nil && len(ips) > 0 {
			return ips, ttl, nil
		}
		r.logger.Debugf("TTL extraction failed, falling back to standard resolution: %v", err)
	}

	// Fallback to standard resolution without TTL
	ips, err := r.lookupIPs(ctx)
	return ips, 0, err
}

// queryDNSWithTTL performs a raw DNS query to extract TTL information
func (r *EndpointResolver) queryDNSWithTTL(ctx context.Context) ([]netip.Addr, time.Duration, error) {
	client := &dns.Client{
		Timeout: 10 * time.Second,
	}

	// Try A record first (IPv4)
	ips, ttl, err := r.queryDNSRecord(ctx, client, dns.TypeA)
	if err == nil && len(ips) > 0 {
		// Also try AAAA record (IPv6) and combine results
		ipv6IPs, ipv6TTL, ipv6Err := r.queryDNSRecord(ctx, client, dns.TypeAAAA)
		if ipv6Err == nil && len(ipv6IPs) > 0 {
			// Use the shorter TTL if both are available
			if ipv6TTL > 0 && (ttl == 0 || ipv6TTL < ttl) {
				ttl = ipv6TTL
			}
			ips = append(ips, ipv6IPs...)
		}
		return ips, ttl, nil
	}

	// If A record failed, try AAAA record only
	return r.queryDNSRecord(ctx, client, dns.TypeAAAA)
}

// queryDNSRecord performs a DNS query for a specific record type
func (r *EndpointResolver) queryDNSRecord(ctx context.Context, client *dns.Client, recordType uint16) ([]netip.Addr, time.Duration, error) {
	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn(r.hostname), recordType)

	response, _, err := client.ExchangeContext(ctx, msg, net.JoinHostPort(r.dnsServer, "53"))
	if err != nil {
		return nil, 0, err
	}

	if response.Rcode != dns.RcodeSuccess {
		return nil, 0, fmt.Errorf("DNS query failed with rcode: %d", response.Rcode)
	}

	var ips []netip.Addr
	var minTTL time.Duration

	for _, answer := range response.Answer {
		var ip netip.Addr
		var ttl time.Duration = time.Duration(answer.Header().Ttl) * time.Second

		switch record := answer.(type) {
		case *dns.A:
			if addr, ok := netip.AddrFromSlice(record.A); ok {
				ip = addr
			}
		case *dns.AAAA:
			if addr, ok := netip.AddrFromSlice(record.AAAA); ok {
				ip = addr
			}
		default:
			continue
		}

		if ip.IsValid() {
			ips = append(ips, ip)
			if minTTL == 0 || ttl < minTTL {
				minTTL = ttl
			}
		}
	}

	return ips, minTTL, nil
}

// getNextResolveInterval calculates the next resolution interval based on TTL or configured interval
func (r *EndpointResolver) getNextResolveInterval() time.Duration {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.useTTL && r.lastTTL > 0 {
		// Use TTL but enforce minimum interval
		interval := r.lastTTL
		if interval < r.minInterval {
			interval = r.minInterval
		}
		r.logger.Debugf("Using TTL-based interval: %v (TTL: %v, min: %v)", interval, r.lastTTL, r.minInterval)
		return interval
	}

	// Use configured interval or default
	interval := r.resolveInterval
	if interval == 0 {
		interval = r.minInterval
	}

	r.logger.Debugf("Using configured interval: %v", interval)
	return interval
}
