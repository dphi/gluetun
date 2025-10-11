package wireguard

import (
	"net/netip"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/device"
)

func Test_New(t *testing.T) {
	t.Parallel()

	const validKeyString = "oMNSf/zJ0pt1ciy+qIRk8Rlyfs9accwuRLnKd85Yl1Q="
	logger := NewMockLogger(nil)
	netLinker := NewMockNetLinker(nil)

	testCases := map[string]struct {
		settings  Settings
		wireguard *Wireguard
		err       error
	}{
		"bad settings": {
			settings: Settings{
				PrivateKey: "",
			},
			err: ErrPrivateKeyMissing,
		},
		"minimal valid settings": {
			settings: Settings{
				PrivateKey: validKeyString,
				PublicKey:  validKeyString,
				Endpoint:   netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 0),
				Addresses: []netip.Prefix{
					netip.PrefixFrom(netip.AddrFrom4([4]byte{5, 6, 7, 8}), 32),
				},
				FirewallMark: 100,
			},
			wireguard: &Wireguard{
				logger:  logger,
				netlink: netLinker,
				settings: Settings{
					InterfaceName: "wg0",
					PrivateKey:    validKeyString,
					PublicKey:     validKeyString,
					Endpoint:      netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 51820),
					Addresses: []netip.Prefix{
						netip.PrefixFrom(netip.AddrFrom4([4]byte{5, 6, 7, 8}), 32),
					},
					AllowedIPs: []netip.Prefix{
						allIPv4(),
					},
					FirewallMark:   100,
					MTU:            device.DefaultMTU,
					IPv6:           ptr(false),
					Implementation: "auto",
				},
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			wireguard, err := New(testCase.settings, netLinker, logger)

			if testCase.err != nil {
				require.Error(t, err)
				assert.Equal(t, testCase.err.Error(), err.Error())
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, testCase.wireguard, wireguard)
		})
	}
}
func Test_NewWireguardManager(t *testing.T) {
	t.Parallel()

	const validKeyString = "oMNSf/zJ0pt1ciy+qIRk8Rlyfs9accwuRLnKd85Yl1Q="

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	logger := NewMockLogger(ctrl)
	netLinker := NewMockNetLinker(ctrl)

	// Set up basic expectations for logger
	logger.EXPECT().Info(gomock.Any()).AnyTimes()
	logger.EXPECT().Debug(gomock.Any()).AnyTimes()
	logger.EXPECT().Debugf(gomock.Any(), gomock.Any()).AnyTimes()

	testCases := map[string]struct {
		settings      Settings
		expectedType  string // "standard" or "dynamic"
		expectError   bool
		errorContains string
	}{
		"IP-based configuration creates standard WireGuard": {
			settings: Settings{
				PrivateKey: validKeyString,
				PublicKey:  validKeyString,
				Endpoint:   netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 51820),
				Addresses: []netip.Prefix{
					netip.PrefixFrom(netip.AddrFrom4([4]byte{5, 6, 7, 8}), 32),
				},
				FirewallMark: 100,
			},
			expectedType: "standard",
		},
		"hostname-based configuration creates dynamic WireGuard": {
			settings: Settings{
				PrivateKey:       validKeyString,
				PublicKey:        validKeyString,
				EndpointHostname: "vpn.example.com",
				Endpoint:         netip.AddrPortFrom(netip.AddrFrom4([4]byte{0, 0, 0, 0}), 51820),
				Addresses: []netip.Prefix{
					netip.PrefixFrom(netip.AddrFrom4([4]byte{5, 6, 7, 8}), 32),
				},
				FirewallMark:        100,
				ResolveInterval:     5 * time.Minute,
				HealthCheckInterval: 30 * time.Second,
			},
			expectedType: "dynamic",
		},
		"empty hostname configuration creates standard WireGuard": {
			settings: Settings{
				PrivateKey: validKeyString,
				PublicKey:  validKeyString,
				Endpoint:   netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 51820),
				Addresses: []netip.Prefix{
					netip.PrefixFrom(netip.AddrFrom4([4]byte{5, 6, 7, 8}), 32),
				},
				FirewallMark:     100,
				EndpointHostname: "", // Empty hostname should use standard WireGuard
			},
			expectedType: "standard",
		},
		"invalid base settings return error": {
			settings: Settings{
				PrivateKey:       "", // Invalid private key
				EndpointHostname: "vpn.example.com",
			},
			expectError:   true,
			errorContains: "private key",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			manager, err := NewWireguardManager(testCase.settings, netLinker, logger)

			if testCase.expectError {
				require.Error(t, err)
				if testCase.errorContains != "" {
					assert.Contains(t, err.Error(), testCase.errorContains)
				}
				return
			}

			require.NoError(t, err)
			require.NotNil(t, manager)

			// Verify the correct type was created
			switch testCase.expectedType {
			case "standard":
				_, ok := manager.(*Wireguard)
				assert.True(t, ok, "Expected standard Wireguard instance")
			case "dynamic":
				_, ok := manager.(*DynamicWireguard)
				assert.True(t, ok, "Expected DynamicWireguard instance")
			}

			// Verify the manager implements the WireguardInterface
			var _ WireguardInterface = manager
		})
	}
}

func Test_WireguardInterface_Implementation(t *testing.T) {
	t.Parallel()

	const validKeyString = "oMNSf/zJ0pt1ciy+qIRk8Rlyfs9accwuRLnKd85Yl1Q="

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	logger := NewMockLogger(ctrl)
	netLinker := NewMockNetLinker(ctrl)

	// Set up basic expectations for logger
	logger.EXPECT().Info(gomock.Any()).AnyTimes()
	logger.EXPECT().Debug(gomock.Any()).AnyTimes()
	logger.EXPECT().Debugf(gomock.Any(), gomock.Any()).AnyTimes()

	testCases := map[string]struct {
		settings     Settings
		expectedType string
	}{
		"standard WireGuard for IP endpoint": {
			settings: Settings{
				PrivateKey: validKeyString,
				PublicKey:  validKeyString,
				Endpoint:   netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 51820),
				Addresses: []netip.Prefix{
					netip.PrefixFrom(netip.AddrFrom4([4]byte{5, 6, 7, 8}), 32),
				},
				FirewallMark: 100,
			},
			expectedType: "standard",
		},
		"dynamic WireGuard for hostname endpoint": {
			settings: Settings{
				PrivateKey:       validKeyString,
				PublicKey:        validKeyString,
				EndpointHostname: "vpn.example.com",
				Endpoint:         netip.AddrPortFrom(netip.AddrFrom4([4]byte{0, 0, 0, 0}), 51820),
				Addresses: []netip.Prefix{
					netip.PrefixFrom(netip.AddrFrom4([4]byte{5, 6, 7, 8}), 32),
				},
				FirewallMark:        100,
				ResolveInterval:     5 * time.Minute,
				HealthCheckInterval: 30 * time.Second,
			},
			expectedType: "dynamic",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			manager, err := NewWireguardManager(testCase.settings, netLinker, logger)
			require.NoError(t, err)
			require.NotNil(t, manager)

			// Verify the correct type was created
			switch testCase.expectedType {
			case "standard":
				_, ok := manager.(*Wireguard)
				assert.True(t, ok, "Expected standard Wireguard instance")
			case "dynamic":
				_, ok := manager.(*DynamicWireguard)
				assert.True(t, ok, "Expected DynamicWireguard instance")
			}

			// Verify the manager implements the WireguardInterface
			var _ WireguardInterface = manager
		})
	}
}
