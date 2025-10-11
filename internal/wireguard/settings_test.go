package wireguard

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/device"
)

func ptr[T any](v T) *T { return &v }

func Test_Settings_SetDefaults(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		original Settings
		expected Settings
	}{
		"empty settings": {
			expected: Settings{
				InterfaceName:  "wg0",
				FirewallMark:   51820,
				AllowedIPs:     []netip.Prefix{allIPv4()},
				MTU:            device.DefaultMTU,
				IPv6:           ptr(false),
				Implementation: "auto",
			},
		},
		"default endpoint port": {
			original: Settings{
				Endpoint: netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 0),
			},
			expected: Settings{
				InterfaceName:  "wg0",
				FirewallMark:   51820,
				Endpoint:       netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 51820),
				AllowedIPs:     []netip.Prefix{allIPv4()},
				MTU:            device.DefaultMTU,
				IPv6:           ptr(false),
				Implementation: "auto",
			},
		},
		"not empty settings": {
			original: Settings{
				InterfaceName:  "wg1",
				FirewallMark:   999,
				Endpoint:       netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 9999),
				AllowedIPs:     []netip.Prefix{allIPv4()},
				MTU:            device.DefaultMTU,
				IPv6:           ptr(true),
				Implementation: "userspace",
			},
			expected: Settings{
				InterfaceName:  "wg1",
				FirewallMark:   999,
				Endpoint:       netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 9999),
				AllowedIPs:     []netip.Prefix{allIPv4()},
				MTU:            device.DefaultMTU,
				IPv6:           ptr(true),
				Implementation: "userspace",
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			testCase.original.SetDefaults()

			assert.Equal(t, testCase.expected, testCase.original)
		})
	}
}

func Test_Settings_Check(t *testing.T) {
	t.Parallel()

	const (
		validKey1 = "oMNSf/zJ0pt1ciy+qIRk8Rlyfs9accwuRLnKd85Yl1Q="
		validKey2 = "aPjc9US5ICB30D1P4glR9tO7bkB2Ga+KZiFqnoypBHk="
	)

	testCases := map[string]struct {
		settings   Settings
		errWrapped error
		errMessage string
	}{
		"empty settings": {
			errWrapped: ErrInterfaceNameInvalid,
			errMessage: "invalid interface name: ",
		},
		"bad interface name": {
			settings: Settings{
				InterfaceName: "$H1T",
			},
			errWrapped: ErrInterfaceNameInvalid,
			errMessage: "invalid interface name: $H1T",
		},
		"empty private key": {
			settings: Settings{
				InterfaceName: "wg0",
			},
			errWrapped: ErrPrivateKeyMissing,
			errMessage: "private key is missing",
		},
		"bad private key": {
			settings: Settings{
				InterfaceName: "wg0",
				PrivateKey:    "bad key",
			},
			errWrapped: ErrPrivateKeyInvalid,
			errMessage: "cannot parse private key",
		},
		"empty public key": {
			settings: Settings{
				InterfaceName: "wg0",
				PrivateKey:    validKey1,
			},
			errWrapped: ErrPublicKeyMissing,
			errMessage: "public key is missing",
		},
		"bad public key": {
			settings: Settings{
				InterfaceName: "wg0",
				PrivateKey:    validKey1,
				PublicKey:     "bad key",
			},
			errWrapped: ErrPublicKeyInvalid,
			errMessage: "cannot parse public key: bad key",
		},
		"bad preshared key": {
			settings: Settings{
				InterfaceName: "wg0",
				PrivateKey:    validKey1,
				PublicKey:     validKey2,
				PreSharedKey:  "bad key",
			},
			errWrapped: ErrPreSharedKeyInvalid,
			errMessage: "cannot parse pre-shared key",
		},
		"invalid endpoint address": {
			settings: Settings{
				InterfaceName: "wg0",
				PrivateKey:    validKey1,
				PublicKey:     validKey2,
			},
			errWrapped: ErrEndpointRequired,
			errMessage: "either endpoint IP or hostname is required",
		},
		"zero endpoint port": {
			settings: Settings{
				InterfaceName: "wg0",
				PrivateKey:    validKey1,
				PublicKey:     validKey2,
				Endpoint:      netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 0),
			},
			errWrapped: ErrEndpointPortMissing,
			errMessage: "endpoint port is missing",
		},
		"no address": {
			settings: Settings{
				InterfaceName: "wg0",
				PrivateKey:    validKey1,
				PublicKey:     validKey2,
				Endpoint:      netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 51820),
			},
			errWrapped: ErrAddressMissing,
			errMessage: "interface address is missing",
		},
		"invalid address": {
			settings: Settings{
				InterfaceName: "wg0",
				PrivateKey:    validKey1,
				PublicKey:     validKey2,
				Endpoint:      netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 51820),
				Addresses:     []netip.Prefix{{}},
			},
			errWrapped: ErrAddressNotValid,
			errMessage: "interface address is not valid: for address 1 of 1",
		},

		"no allowed IP": {
			settings: Settings{
				InterfaceName: "wg0",
				PrivateKey:    validKey1,
				PublicKey:     validKey2,
				Endpoint:      netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 51820),
				Addresses: []netip.Prefix{
					netip.PrefixFrom(netip.AddrFrom4([4]byte{5, 6, 7, 8}), 24),
				},
			},
			errWrapped: ErrAllowedIPsMissing,
			errMessage: "allowed IPs are missing",
		},
		"invalid allowed IP": {
			settings: Settings{
				InterfaceName: "wg0",
				PrivateKey:    validKey1,
				PublicKey:     validKey2,
				Endpoint:      netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 51820),
				Addresses: []netip.Prefix{
					netip.PrefixFrom(netip.AddrFrom4([4]byte{5, 6, 7, 8}), 24),
				},
				AllowedIPs: []netip.Prefix{{}},
			},
			errWrapped: ErrAllowedIPNotValid,
			errMessage: "allowed IP is not valid: for allowed IP 1 of 1",
		},
		"ipv6 allowed IP": {
			settings: Settings{
				InterfaceName: "wg0",
				PrivateKey:    validKey1,
				PublicKey:     validKey2,
				Endpoint:      netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 51820),
				Addresses: []netip.Prefix{
					netip.PrefixFrom(netip.AddrFrom4([4]byte{5, 6, 7, 8}), 24),
				},
				AllowedIPs: []netip.Prefix{
					allIPv6(),
				},
				IPv6: ptrTo(false),
			},
			errWrapped: ErrAllowedIPv6NotSupported,
			errMessage: "allowed IPv6 address not supported: for allowed IP ::/0",
		},
		"zero firewall mark": {
			settings: Settings{
				InterfaceName: "wg0",
				PrivateKey:    validKey1,
				PublicKey:     validKey2,
				Endpoint:      netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 51820),
				AllowedIPs:    []netip.Prefix{allIPv4()},
				Addresses: []netip.Prefix{
					netip.PrefixFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 24),
				},
			},
			errWrapped: ErrFirewallMarkMissing,
			errMessage: "firewall mark is missing",
		},
		"missing_MTU": {
			settings: Settings{
				InterfaceName: "wg0",
				PrivateKey:    validKey1,
				PublicKey:     validKey2,
				Endpoint:      netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 51820),
				AllowedIPs:    []netip.Prefix{allIPv4()},
				Addresses: []netip.Prefix{
					netip.PrefixFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 24),
				},
				FirewallMark: 999,
			},
			errWrapped: ErrMTUMissing,
			errMessage: "MTU is missing",
		},
		"invalid implementation": {
			settings: Settings{
				InterfaceName: "wg0",
				PrivateKey:    validKey1,
				PublicKey:     validKey2,
				Endpoint:      netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 51820),
				AllowedIPs:    []netip.Prefix{allIPv4()},
				Addresses: []netip.Prefix{
					netip.PrefixFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 24),
				},
				FirewallMark:   999,
				MTU:            1420,
				Implementation: "x",
			},
			errWrapped: ErrImplementationInvalid,
			errMessage: "invalid implementation: x",
		},
		"all valid": {
			settings: Settings{
				InterfaceName: "wg0",
				PrivateKey:    validKey1,
				PublicKey:     validKey2,
				Endpoint:      netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 51820),
				AllowedIPs: []netip.Prefix{
					allIPv6(),
				},
				Addresses: []netip.Prefix{
					netip.PrefixFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 24),
				},
				FirewallMark:   999,
				MTU:            1420,
				IPv6:           ptrTo(true),
				Implementation: "userspace",
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := testCase.settings.Check()

			assert.ErrorIs(t, err, testCase.errWrapped)
			if testCase.errWrapped != nil {
				assert.EqualError(t, err, testCase.errMessage)
			}
		})
	}
}

func Test_Settings_validateEndpoint(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		settings   Settings
		errWrapped error
		errMessage string
	}{
		"no endpoint configuration": {
			settings:   Settings{},
			errWrapped: ErrEndpointRequired,
			errMessage: "either endpoint IP or hostname is required",
		},
		"both IP and hostname provided": {
			settings: Settings{
				Endpoint:         netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 51820),
				EndpointHostname: "example.com",
			},
			errWrapped: ErrEndpointMutuallyExclusive,
			errMessage: "endpoint IP and hostname are mutually exclusive",
		},
		"valid IP endpoint": {
			settings: Settings{
				Endpoint: netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 51820),
			},
		},
		"valid hostname endpoint": {
			settings: Settings{
				EndpointHostname:    "example.com",
				ResolveInterval:     60 * time.Second,
				HealthCheckInterval: 30 * time.Second,
			},
		},
		"invalid hostname format - empty": {
			settings: Settings{
				EndpointHostname: "",
			},
			errWrapped: ErrEndpointRequired,
			errMessage: "either endpoint IP or hostname is required",
		},
		"invalid hostname format - invalid characters": {
			settings: Settings{
				EndpointHostname: "invalid_hostname!",
			},
			errWrapped: ErrEndpointHostnameInvalid,
			errMessage: "endpoint hostname is not valid: invalid_hostname!",
		},
		"invalid hostname format - starts with hyphen": {
			settings: Settings{
				EndpointHostname: "-example.com",
			},
			errWrapped: ErrEndpointHostnameInvalid,
			errMessage: "endpoint hostname is not valid: -example.com",
		},
		"invalid hostname format - ends with hyphen": {
			settings: Settings{
				EndpointHostname: "example-.com",
			},
			errWrapped: ErrEndpointHostnameInvalid,
			errMessage: "endpoint hostname is not valid: example-.com",
		},
		"valid hostname with subdomain": {
			settings: Settings{
				EndpointHostname:    "vpn.example.com",
				ResolveInterval:     60 * time.Second,
				HealthCheckInterval: 30 * time.Second,
			},
		},
		"valid hostname with numbers": {
			settings: Settings{
				EndpointHostname:    "vpn1.example2.com",
				ResolveInterval:     60 * time.Second,
				HealthCheckInterval: 30 * time.Second,
			},
		},
		"negative resolve interval": {
			settings: Settings{
				EndpointHostname:    "example.com",
				ResolveInterval:     -1 * time.Second,
				HealthCheckInterval: 30 * time.Second,
			},
			errWrapped: ErrResolveIntervalInvalid,
			errMessage: "resolve interval is invalid: resolve interval cannot be negative",
		},
		"resolve interval too short": {
			settings: Settings{
				EndpointHostname:    "example.com",
				ResolveInterval:     30 * time.Second, // Less than 60 seconds
				HealthCheckInterval: 30 * time.Second,
			},
			errWrapped: ErrResolveIntervalInvalid,
			errMessage: "resolve interval is invalid: resolve interval must be at least 60 seconds",
		},
		"negative health check interval": {
			settings: Settings{
				EndpointHostname:    "example.com",
				ResolveInterval:     60 * time.Second,
				HealthCheckInterval: -1 * time.Second,
			},
			errWrapped: ErrHealthCheckIntervalInvalid,
			errMessage: "health check interval is invalid: health check interval cannot be negative",
		},
		"health check interval too short": {
			settings: Settings{
				EndpointHostname:    "example.com",
				ResolveInterval:     60 * time.Second,
				HealthCheckInterval: 500 * time.Millisecond, // Less than 1 second
			},
			errWrapped: ErrHealthCheckIntervalInvalid,
			errMessage: "health check interval is invalid: health check interval must be at least 1 second",
		},
		"IP endpoint with zero port": {
			settings: Settings{
				Endpoint: netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 0),
			},
			errWrapped: ErrEndpointPortMissing,
			errMessage: "endpoint port is missing",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := testCase.settings.validateEndpoint()

			if testCase.errWrapped != nil {
				assert.ErrorIs(t, err, testCase.errWrapped)
				assert.EqualError(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_Settings_SetDefaults_Hostname(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		original Settings
		expected Settings
	}{
		"hostname with default intervals": {
			original: Settings{
				EndpointHostname: "example.com",
			},
			expected: Settings{
				InterfaceName:       "wg0",
				EndpointHostname:    "example.com",
				ResolveInterval:     60 * time.Second,
				HealthCheckInterval: 30 * time.Second,
				FirewallMark:        51820,
				AllowedIPs:          []netip.Prefix{allIPv4()},
				MTU:                 device.DefaultMTU,
				IPv6:                ptr(false),
				Implementation:      "auto",
			},
		},
		"hostname with custom intervals": {
			original: Settings{
				EndpointHostname:    "example.com",
				ResolveInterval:     120 * time.Second,
				HealthCheckInterval: 60 * time.Second,
			},
			expected: Settings{
				InterfaceName:       "wg0",
				EndpointHostname:    "example.com",
				ResolveInterval:     120 * time.Second,
				HealthCheckInterval: 60 * time.Second,
				FirewallMark:        51820,
				AllowedIPs:          []netip.Prefix{allIPv4()},
				MTU:                 device.DefaultMTU,
				IPv6:                ptr(false),
				Implementation:      "auto",
			},
		},
		"hostname with too short resolve interval": {
			original: Settings{
				EndpointHostname:    "example.com",
				ResolveInterval:     30 * time.Second, // Will be enforced to 60s
				HealthCheckInterval: 30 * time.Second,
			},
			expected: Settings{
				InterfaceName:       "wg0",
				EndpointHostname:    "example.com",
				ResolveInterval:     60 * time.Second, // Enforced minimum
				HealthCheckInterval: 30 * time.Second,
				FirewallMark:        51820,
				AllowedIPs:          []netip.Prefix{allIPv4()},
				MTU:                 device.DefaultMTU,
				IPv6:                ptr(false),
				Implementation:      "auto",
			},
		},
		"hostname with too short health check interval": {
			original: Settings{
				EndpointHostname:    "example.com",
				ResolveInterval:     60 * time.Second,
				HealthCheckInterval: 500 * time.Millisecond, // Will be enforced to 1s
			},
			expected: Settings{
				InterfaceName:       "wg0",
				EndpointHostname:    "example.com",
				ResolveInterval:     60 * time.Second,
				HealthCheckInterval: 1 * time.Second, // Enforced minimum
				FirewallMark:        51820,
				AllowedIPs:          []netip.Prefix{allIPv4()},
				MTU:                 device.DefaultMTU,
				IPv6:                ptr(false),
				Implementation:      "auto",
			},
		},
		"IP endpoint - no hostname intervals": {
			original: Settings{
				Endpoint: netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 51820),
			},
			expected: Settings{
				InterfaceName:  "wg0",
				Endpoint:       netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 51820),
				FirewallMark:   51820,
				AllowedIPs:     []netip.Prefix{allIPv4()},
				MTU:            device.DefaultMTU,
				IPv6:           ptr(false),
				Implementation: "auto",
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			testCase.original.SetDefaults()

			assert.Equal(t, testCase.expected, testCase.original)
		})
	}
}

func Test_Settings_GetEffectiveResolveInterval(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		settings Settings
		dnsTTL   time.Duration
		expected time.Duration
	}{
		"IP-based endpoint": {
			settings: Settings{
				Endpoint: netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 51820),
			},
			dnsTTL:   300 * time.Second,
			expected: 0, // Not applicable for IP-based endpoints
		},
		"hostname with valid TTL": {
			settings: Settings{
				EndpointHostname: "example.com",
				ResolveInterval:  120 * time.Second,
			},
			dnsTTL:   300 * time.Second,
			expected: 300 * time.Second, // Use TTL
		},
		"hostname with TTL below minimum": {
			settings: Settings{
				EndpointHostname: "example.com",
				ResolveInterval:  120 * time.Second,
			},
			dnsTTL:   30 * time.Second,
			expected: 60 * time.Second, // Enforce minimum
		},
		"hostname with zero TTL": {
			settings: Settings{
				EndpointHostname: "example.com",
				ResolveInterval:  120 * time.Second,
			},
			dnsTTL:   0,
			expected: 120 * time.Second, // Fallback to configured interval
		},
		"hostname with negative TTL": {
			settings: Settings{
				EndpointHostname: "example.com",
				ResolveInterval:  120 * time.Second,
			},
			dnsTTL:   -1 * time.Second,
			expected: 120 * time.Second, // Fallback to configured interval
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			result := testCase.settings.GetEffectiveResolveInterval(testCase.dnsTTL)

			assert.Equal(t, testCase.expected, result)
		})
	}
}

func Test_Settings_GetEffectiveHealthCheckInterval(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		settings Settings
		expected time.Duration
	}{
		"IP-based endpoint": {
			settings: Settings{
				Endpoint: netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 51820),
			},
			expected: 0, // Not applicable for IP-based endpoints
		},
		"hostname-based endpoint": {
			settings: Settings{
				EndpointHostname:    "example.com",
				HealthCheckInterval: 45 * time.Second,
			},
			expected: 45 * time.Second,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			result := testCase.settings.GetEffectiveHealthCheckInterval()

			assert.Equal(t, testCase.expected, result)
		})
	}
}

func Test_Settings_IsHostnameBased(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		settings Settings
		expected bool
	}{
		"IP-based endpoint": {
			settings: Settings{
				Endpoint: netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 51820),
			},
			expected: false,
		},
		"hostname-based endpoint": {
			settings: Settings{
				EndpointHostname: "example.com",
			},
			expected: true,
		},
		"empty settings": {
			settings: Settings{},
			expected: false,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			result := testCase.settings.IsHostnameBased()

			assert.Equal(t, testCase.expected, result)
		})
	}
}

func Test_Settings_resolveHostnameEndpoint(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		settings    Settings
		expectError bool
		errorMsg    string
	}{
		"no hostname": {
			settings: Settings{
				Endpoint: netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 51820),
			},
			expectError: false,
		},
		"valid hostname": {
			settings: Settings{
				EndpointHostname: "google.com", // Use a real hostname that should resolve
				ResolveInterval:  60 * time.Second,
			},
			expectError: false,
		},
		"invalid hostname": {
			settings: Settings{
				EndpointHostname: "this-hostname-should-not-exist-12345.invalid",
				ResolveInterval:  60 * time.Second,
			},
			expectError: true,
			errorMsg:    "endpoint hostname resolution failed",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			err := testCase.settings.resolveHostnameEndpoint(ctx)

			if testCase.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), testCase.errorMsg)
			} else {
				assert.NoError(t, err)
				// If hostname was provided, endpoint should be updated
				if testCase.settings.EndpointHostname != "" {
					assert.True(t, testCase.settings.Endpoint.Addr().IsValid())
					assert.NotEqual(t, uint16(0), testCase.settings.Endpoint.Port())
				}
			}
		})
	}
}

func Test_Settings_Check_WithHostname(t *testing.T) {
	t.Parallel()

	const (
		validKey1 = "oMNSf/zJ0pt1ciy+qIRk8Rlyfs9accwuRLnKd85Yl1Q="
		validKey2 = "aPjc9US5ICB30D1P4glR9tO7bkB2Ga+KZiFqnoypBHk="
	)

	testCases := map[string]struct {
		settings   Settings
		errWrapped error
		errMessage string
	}{
		"valid hostname configuration": {
			settings: Settings{
				InterfaceName:       "wg0",
				PrivateKey:          validKey1,
				PublicKey:           validKey2,
				EndpointHostname:    "example.com",
				ResolveInterval:     60 * time.Second,
				HealthCheckInterval: 30 * time.Second,
				AllowedIPs:          []netip.Prefix{allIPv4()},
				Addresses: []netip.Prefix{
					netip.PrefixFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 24),
				},
				FirewallMark:   999,
				MTU:            1420,
				IPv6:           ptr(false),
				Implementation: "userspace",
			},
		},
		"hostname with both IP and hostname": {
			settings: Settings{
				InterfaceName:    "wg0",
				PrivateKey:       validKey1,
				PublicKey:        validKey2,
				Endpoint:         netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 51820),
				EndpointHostname: "example.com",
			},
			errWrapped: ErrEndpointMutuallyExclusive,
			errMessage: "endpoint IP and hostname are mutually exclusive",
		},
		"hostname with invalid format": {
			settings: Settings{
				InterfaceName:    "wg0",
				PrivateKey:       validKey1,
				PublicKey:        validKey2,
				EndpointHostname: "invalid_hostname!",
			},
			errWrapped: ErrEndpointHostnameInvalid,
			errMessage: "endpoint hostname is not valid: invalid_hostname!",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := testCase.settings.Check()

			if testCase.errWrapped != nil {
				assert.ErrorIs(t, err, testCase.errWrapped)
				assert.EqualError(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func toStringPtr(s string) *string { return &s }

func Test_ToLinesSettings_setDefaults(t *testing.T) {
	t.Parallel()

	settings := ToLinesSettings{
		Indent: toStringPtr("indent"),
	}

	someFunc := func(settings ToLinesSettings) {
		settings.setDefaults()
		expectedSettings := ToLinesSettings{
			Indent:          toStringPtr("indent"),
			FieldPrefix:     toStringPtr("├── "),
			LastFieldPrefix: toStringPtr("└── "),
		}
		assert.Equal(t, expectedSettings, settings)
	}
	someFunc(settings)

	untouchedSettings := ToLinesSettings{
		Indent: toStringPtr("indent"),
	}
	assert.Equal(t, untouchedSettings, settings)
}

func Test_Settings_String(t *testing.T) {
	t.Parallel()

	settings := Settings{
		InterfaceName:  "wg0",
		IPv6:           ptr(true),
		Implementation: "x",
	}
	const expected = `├── Interface name: wg0
├── Private key: not set
├── Pre shared key: not set
├── Endpoint: not set
├── IPv6: enabled
├── Implementation: x
└── Addresses: not set`
	s := settings.String()
	assert.Equal(t, expected, s)
}

func Test_Settings_Lines(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		settings     Settings
		lineSettings ToLinesSettings
		lines        []string
	}{
		"empty settings": {
			settings: Settings{
				IPv6: ptr(false),
			},
			lines: []string{
				"├── Interface name: ",
				"├── Private key: not set",
				"├── Pre shared key: not set",
				"├── Endpoint: not set",
				"├── IPv6: disabled",
				"├── Implementation: ",
				"└── Addresses: not set",
			},
		},
		"settings all set": {
			settings: Settings{
				InterfaceName: "wg0",
				PrivateKey:    "private key",
				PublicKey:     "public key",
				PreSharedKey:  "pre-shared key",
				Endpoint:      netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 51820),
				FirewallMark:  999,
				RulePriority:  888,
				Addresses: []netip.Prefix{
					netip.PrefixFrom(netip.AddrFrom4([4]byte{1, 1, 1, 1}), 24),
					netip.PrefixFrom(netip.AddrFrom4([4]byte{2, 2, 2, 2}), 32),
				},
				IPv6:           ptr(true),
				Implementation: "userspace",
			},
			lines: []string{
				"├── Interface name: wg0",
				"├── Private key: set",
				"├── PublicKey: public key",
				"├── Pre shared key: set",
				"├── Endpoint: 1.2.3.4:51820",
				"├── IPv6: enabled",
				"├── Firewall mark: 999",
				"├── Rule priority: 888",
				"├── Implementation: userspace",
				"└── Addresses:",
				"    ├── 1.1.1.1/24",
				"    └── 2.2.2.2/32",
			},
		},
		"custom line settings": {
			lineSettings: ToLinesSettings{
				Indent:          toStringPtr("  "),
				FieldPrefix:     toStringPtr("- "),
				LastFieldPrefix: toStringPtr("* "),
			},
			settings: Settings{
				InterfaceName: "wg0",
				Addresses: []netip.Prefix{
					netip.PrefixFrom(netip.AddrFrom4([4]byte{1, 1, 1, 1}), 24),
					netip.PrefixFrom(netip.AddrFrom4([4]byte{2, 2, 2, 2}), 32),
				},
				IPv6: ptr(false),
			},
			lines: []string{
				"- Interface name: wg0",
				"- Private key: not set",
				"- Pre shared key: not set",
				"- Endpoint: not set",
				"- IPv6: disabled",
				"- Implementation: ",
				"* Addresses:",
				"  - 1.1.1.1/24",
				"  * 2.2.2.2/32",
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			lines := testCase.settings.ToLines(testCase.lineSettings)

			assert.Equal(t, testCase.lines, lines)
		})
	}
}
