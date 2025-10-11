package wireguard

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestNewConnectionMonitor(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := NewMockWgctrlClient(ctrl)
	mockLogger := NewMockLogger(ctrl)

	testCases := map[string]struct {
		settings MonitorSettings
		expected *ConnectionMonitor
	}{
		"default settings": {
			settings: MonitorSettings{
				InterfaceName: "wg0",
			},
			expected: &ConnectionMonitor{
				client:           mockClient,
				interfaceName:    "wg0",
				logger:           mockLogger,
				healthInterval:   30 * time.Second,
				handshakeTimeout: 2 * time.Minute,
			},
		},
		"custom settings": {
			settings: MonitorSettings{
				InterfaceName:       "wg1",
				HealthInterval:      10 * time.Second,
				HandshakeTimeout:    5 * time.Minute,
				PersistentKeepalive: true,
			},
			expected: &ConnectionMonitor{
				client:              mockClient,
				interfaceName:       "wg1",
				logger:              mockLogger,
				healthInterval:      10 * time.Second,
				handshakeTimeout:    5 * time.Minute,
				persistentKeepalive: true,
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			monitor := NewConnectionMonitor(testCase.settings, mockClient, mockLogger)

			assert.Equal(t, testCase.expected.interfaceName, monitor.interfaceName)
			assert.Equal(t, testCase.expected.healthInterval, monitor.healthInterval)
			assert.Equal(t, testCase.expected.handshakeTimeout, monitor.handshakeTimeout)
			assert.Equal(t, testCase.expected.persistentKeepalive, monitor.persistentKeepalive)
		})
	}
}

func TestConnectionMonitor_IsHealthy(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := NewMockWgctrlClient(ctrl)
	mockLogger := NewMockLogger(ctrl)

	testCases := map[string]struct {
		setupMocks func()
		expected   bool
		expectErr  bool
	}{
		"device error": {
			setupMocks: func() {
				mockClient.EXPECT().Device("wg0").Return(nil, errors.New("device error"))
			},
			expected:  false,
			expectErr: true,
		},
		"no peers": {
			setupMocks: func() {
				device := &wgtypes.Device{
					Name:  "wg0",
					Peers: []wgtypes.Peer{},
				}
				mockClient.EXPECT().Device("wg0").Return(device, nil)
				mockLogger.EXPECT().Debug("No peers found for WireGuard device")
			},
			expected:  false,
			expectErr: false,
		},
		"no handshake yet": {
			setupMocks: func() {
				device := &wgtypes.Device{
					Name: "wg0",
					Peers: []wgtypes.Peer{
						{
							LastHandshakeTime: time.Time{}, // Zero time
						},
					},
				}
				mockClient.EXPECT().Device("wg0").Return(device, nil)
				mockLogger.EXPECT().Debug("No handshake recorded yet")
			},
			expected:  false,
			expectErr: false,
		},
		"recent handshake - healthy": {
			setupMocks: func() {
				recentTime := time.Now().Add(-30 * time.Second)
				device := &wgtypes.Device{
					Name: "wg0",
					Peers: []wgtypes.Peer{
						{
							LastHandshakeTime: recentTime,
						},
					},
				}
				mockClient.EXPECT().Device("wg0").Return(device, nil)
				mockLogger.EXPECT().Debugf(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
			},
			expected:  true,
			expectErr: false,
		},
		"old handshake - unhealthy": {
			setupMocks: func() {
				oldTime := time.Now().Add(-5 * time.Minute)
				device := &wgtypes.Device{
					Name: "wg0",
					Peers: []wgtypes.Peer{
						{
							LastHandshakeTime: oldTime,
						},
					},
				}
				mockClient.EXPECT().Device("wg0").Return(device, nil)
				mockLogger.EXPECT().Debugf(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
			},
			expected:  false,
			expectErr: false,
		},
		"persistent keepalive - adjusted timeout": {
			setupMocks: func() {
				// Handshake is 90 seconds old, which would normally be unhealthy
				// But with keepalive of 25 seconds, effective timeout is 75 seconds (25*3)
				oldTime := time.Now().Add(-90 * time.Second)
				device := &wgtypes.Device{
					Name: "wg0",
					Peers: []wgtypes.Peer{
						{
							LastHandshakeTime:           oldTime,
							PersistentKeepaliveInterval: 25 * time.Second,
						},
					},
				}
				mockClient.EXPECT().Device("wg0").Return(device, nil)
				mockLogger.EXPECT().Debugf(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
			},
			expected:  false,
			expectErr: false,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			monitor := NewConnectionMonitor(MonitorSettings{
				InterfaceName:    "wg0",
				HealthInterval:   30 * time.Second,
				HandshakeTimeout: 2 * time.Minute,
			}, mockClient, mockLogger)

			testCase.setupMocks()

			healthy, err := monitor.IsHealthy(context.Background())

			if testCase.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, testCase.expected, healthy)
		})
	}
}

func TestConnectionMonitor_GetLastHandshake(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := NewMockWgctrlClient(ctrl)
	mockLogger := NewMockLogger(ctrl)

	testCases := map[string]struct {
		setupMocks    func()
		expectedTime  time.Time
		expectErr     bool
		expectedError string
	}{
		"device error": {
			setupMocks: func() {
				mockClient.EXPECT().Device("wg0").Return(nil, errors.New("device error"))
			},
			expectErr:     true,
			expectedError: "getting device wg0: device error",
		},
		"no peers": {
			setupMocks: func() {
				device := &wgtypes.Device{
					Name:  "wg0",
					Peers: []wgtypes.Peer{},
				}
				mockClient.EXPECT().Device("wg0").Return(device, nil)
			},
			expectErr:     true,
			expectedError: "no peers found for device wg0",
		},
		"success": {
			setupMocks: func() {
				expectedTime := time.Now().Add(-1 * time.Minute)
				device := &wgtypes.Device{
					Name: "wg0",
					Peers: []wgtypes.Peer{
						{
							LastHandshakeTime: expectedTime,
						},
					},
				}
				mockClient.EXPECT().Device("wg0").Return(device, nil)
			},
			expectErr: false,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			monitor := NewConnectionMonitor(MonitorSettings{
				InterfaceName: "wg0",
			}, mockClient, mockLogger)

			testCase.setupMocks()

			handshakeTime, err := monitor.GetLastHandshake()

			if testCase.expectErr {
				assert.Error(t, err)
				if testCase.expectedError != "" {
					assert.EqualError(t, err, testCase.expectedError)
				}
			} else {
				assert.NoError(t, err)
				// For success case, we can't predict exact time, just ensure it's not zero
				assert.False(t, handshakeTime.IsZero())
			}
		})
	}
}

func TestConnectionMonitor_HasPersistentKeepalive(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := NewMockWgctrlClient(ctrl)
	mockLogger := NewMockLogger(ctrl)

	testCases := map[string]struct {
		setupMocks func()
		expected   bool
		expectErr  bool
	}{
		"device error": {
			setupMocks: func() {
				mockClient.EXPECT().Device("wg0").Return(nil, errors.New("device error"))
			},
			expected:  false,
			expectErr: true,
		},
		"no peers": {
			setupMocks: func() {
				device := &wgtypes.Device{
					Name:  "wg0",
					Peers: []wgtypes.Peer{},
				}
				mockClient.EXPECT().Device("wg0").Return(device, nil)
			},
			expected:  false,
			expectErr: false,
		},
		"no keepalive": {
			setupMocks: func() {
				device := &wgtypes.Device{
					Name: "wg0",
					Peers: []wgtypes.Peer{
						{
							PersistentKeepaliveInterval: 0,
						},
					},
				}
				mockClient.EXPECT().Device("wg0").Return(device, nil)
			},
			expected:  false,
			expectErr: false,
		},
		"has keepalive": {
			setupMocks: func() {
				device := &wgtypes.Device{
					Name: "wg0",
					Peers: []wgtypes.Peer{
						{
							PersistentKeepaliveInterval: 25 * time.Second,
						},
					},
				}
				mockClient.EXPECT().Device("wg0").Return(device, nil)
			},
			expected:  true,
			expectErr: false,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			monitor := NewConnectionMonitor(MonitorSettings{
				InterfaceName: "wg0",
			}, mockClient, mockLogger)

			testCase.setupMocks()

			hasKeepalive, err := monitor.HasPersistentKeepalive()

			if testCase.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, testCase.expected, hasKeepalive)
		})
	}
}

func TestConnectionMonitor_UpdatePersistentKeepaliveStatus(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := NewMockWgctrlClient(ctrl)
	mockLogger := NewMockLogger(ctrl)

	testCases := map[string]struct {
		initialKeepalive bool
		setupMocks       func()
		expectErr        bool
	}{
		"error checking status": {
			setupMocks: func() {
				mockClient.EXPECT().Device("wg0").Return(nil, errors.New("device error"))
			},
			expectErr: true,
		},
		"keepalive enabled - status changed": {
			initialKeepalive: false,
			setupMocks: func() {
				device := &wgtypes.Device{
					Name: "wg0",
					Peers: []wgtypes.Peer{
						{
							PersistentKeepaliveInterval: 25 * time.Second,
						},
					},
				}
				mockClient.EXPECT().Device("wg0").Return(device, nil)
				mockLogger.EXPECT().Info("Persistent keepalive detected - will use as part of health monitoring strategy")
			},
			expectErr: false,
		},
		"keepalive disabled - status changed": {
			initialKeepalive: true,
			setupMocks: func() {
				device := &wgtypes.Device{
					Name: "wg0",
					Peers: []wgtypes.Peer{
						{
							PersistentKeepaliveInterval: 0,
						},
					},
				}
				mockClient.EXPECT().Device("wg0").Return(device, nil)
				mockLogger.EXPECT().Info("Persistent keepalive not configured - using standard health monitoring")
			},
			expectErr: false,
		},
		"no status change": {
			initialKeepalive: true,
			setupMocks: func() {
				device := &wgtypes.Device{
					Name: "wg0",
					Peers: []wgtypes.Peer{
						{
							PersistentKeepaliveInterval: 25 * time.Second,
						},
					},
				}
				mockClient.EXPECT().Device("wg0").Return(device, nil)
				// No logger call expected since status didn't change
			},
			expectErr: false,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			monitor := NewConnectionMonitor(MonitorSettings{
				InterfaceName:       "wg0",
				PersistentKeepalive: testCase.initialKeepalive,
			}, mockClient, mockLogger)

			testCase.setupMocks()

			err := monitor.UpdatePersistentKeepaliveStatus()

			if testCase.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConnectionMonitor_ShouldDisablePeriodicResolution(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := NewMockWgctrlClient(ctrl)
	mockLogger := NewMockLogger(ctrl)

	testCases := map[string]struct {
		persistentKeepalive bool
		expected            bool
	}{
		"keepalive enabled": {
			persistentKeepalive: true,
			expected:            true,
		},
		"keepalive disabled": {
			persistentKeepalive: false,
			expected:            false,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			monitor := NewConnectionMonitor(MonitorSettings{
				InterfaceName:       "wg0",
				PersistentKeepalive: testCase.persistentKeepalive,
			}, mockClient, mockLogger)

			result := monitor.ShouldDisablePeriodicResolution()

			assert.Equal(t, testCase.expected, result)
		})
	}
}

func TestConnectionMonitor_StartMonitoring(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := NewMockWgctrlClient(ctrl)
	mockLogger := NewMockLogger(ctrl)

	t.Run("context cancellation", func(t *testing.T) {
		t.Parallel()

		monitor := NewConnectionMonitor(MonitorSettings{
			InterfaceName:    "wg0",
			HealthInterval:   100 * time.Millisecond, // Short interval for testing
			HandshakeTimeout: 2 * time.Minute,
		}, mockClient, mockLogger)

		// Mock initial health check
		device := &wgtypes.Device{
			Name: "wg0",
			Peers: []wgtypes.Peer{
				{
					LastHandshakeTime: time.Now().Add(-30 * time.Second),
				},
			},
		}
		mockClient.EXPECT().Device("wg0").Return(device, nil)
		mockLogger.EXPECT().Info("Starting WireGuard connection health monitoring")
		mockLogger.EXPECT().Debugf(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
		mockLogger.EXPECT().Info("Stopping WireGuard connection health monitoring")

		ctx, cancel := context.WithCancel(context.Background())

		// Start monitoring in a goroutine
		errCh := make(chan error, 1)
		go func() {
			errCh <- monitor.StartMonitoring(ctx, func() {
				// onUnhealthy callback - should not be called in this test
				t.Error("onUnhealthy callback should not be called")
			})
		}()

		// Cancel context after a short delay
		time.Sleep(50 * time.Millisecond)
		cancel()

		// Wait for monitoring to stop
		err := <-errCh
		assert.Equal(t, context.Canceled, err)
	})

	t.Run("unhealthy connection triggers callback", func(t *testing.T) {
		t.Parallel()

		monitor := NewConnectionMonitor(MonitorSettings{
			InterfaceName:    "wg0",
			HealthInterval:   50 * time.Millisecond, // Short interval for testing
			HandshakeTimeout: 1 * time.Minute,
		}, mockClient, mockLogger)

		// Mock initial health check - unhealthy
		device := &wgtypes.Device{
			Name: "wg0",
			Peers: []wgtypes.Peer{
				{
					LastHandshakeTime: time.Now().Add(-5 * time.Minute), // Old handshake
				},
			},
		}
		mockClient.EXPECT().Device("wg0").Return(device, nil).AnyTimes()
		mockLogger.EXPECT().Info("Starting WireGuard connection health monitoring")
		mockLogger.EXPECT().Info("Initial connection is unhealthy, triggering callback")
		mockLogger.EXPECT().Debugf(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
		mockLogger.EXPECT().Info("Unhealthy WireGuard connection detected, triggering callback").AnyTimes()
		mockLogger.EXPECT().Info("Stopping WireGuard connection health monitoring")

		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()

		callbackCount := 0
		errCh := make(chan error, 1)
		go func() {
			errCh <- monitor.StartMonitoring(ctx, func() {
				callbackCount++
			})
		}()

		// Wait for monitoring to complete
		err := <-errCh
		assert.Equal(t, context.DeadlineExceeded, err)
		assert.Greater(t, callbackCount, 0, "onUnhealthy callback should have been called")
	})
}
