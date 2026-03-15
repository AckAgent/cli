//go:build (darwin || linux) && !disable_ble

package transport

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"tinygo.org/x/bluetooth"
)

// BLETransport sends signing requests directly to an iOS device over BLE.
type BLETransport struct {
	adapter        *bluetooth.Adapter
	deviceFilter   string
	scanTimeout    time.Duration
	connectTimeout time.Duration

	serviceUUID  bluetooth.UUID
	requestUUID  bluetooth.UUID
	responseUUID bluetooth.UUID

	enableOnce sync.Once
	enableErr  error
}

// NewBLETransport creates a BLE transport with the given options.
func NewBLETransport(opts BLETransportOptions) *BLETransport {
	scanTimeout := opts.ScanTimeout
	if scanTimeout == 0 {
		scanTimeout = DefaultBLEScanTimeout
	}

	connectTimeout := opts.ConnectTimeout
	if connectTimeout == 0 {
		connectTimeout = DefaultBLEConnectTimeout
	}

	serviceUUID, _ := bluetooth.ParseUUID(BLEServiceUUID)
	requestUUID, _ := bluetooth.ParseUUID(BLERequestCharacteristicUUID)
	responseUUID, _ := bluetooth.ParseUUID(BLEResponseCharacteristicUUID)

	return &BLETransport{
		adapter:        bluetooth.DefaultAdapter,
		deviceFilter:   opts.DeviceFilter,
		scanTimeout:    scanTimeout,
		connectTimeout: connectTimeout,
		serviceUUID:    serviceUUID,
		requestUUID:    requestUUID,
		responseUUID:   responseUUID,
	}
}

// Name returns the transport name.
func (t *BLETransport) Name() string {
	return "bluetooth"
}

// Priority returns the transport priority.
func (t *BLETransport) Priority() int {
	return 10
}

// IsAvailable checks if any compatible BLE devices are discoverable.
func (t *BLETransport) IsAvailable(ctx context.Context) (bool, error) {
	if err := t.ensureEnabled(); err != nil {
		return false, err
	}
	return true, nil
}

// Send sends a signing request via BLE and waits for a response.
func (t *BLETransport) Send(ctx context.Context, req *Request, timeout time.Duration) (*Response, error) {
	if err := t.ensureEnabled(); err != nil {
		return nil, err
	}

	device, err := t.findDevice(ctx)
	if err != nil {
		return nil, err
	}

	connCtx, cancel := context.WithTimeout(ctx, t.connectTimeout)
	defer cancel()

	bleDevice, err := t.connect(connCtx, device.address)
	if err != nil {
		return nil, err
	}
	defer bleDevice.Disconnect()

	requestChar, responseChar, err := t.discoverCharacteristics(bleDevice)
	if err != nil {
		return nil, err
	}

	responseCh := make(chan []byte, 1)
	reassembler := newBLEReassembler()
	var reassemblerMu sync.Mutex

	if err := responseChar.EnableNotifications(func(buf []byte) {
		fragment, ok := decodeBLEFragment(buf)
		if !ok {
			return
		}
		reassemblerMu.Lock()
		complete := reassembler.addFragment(fragment)
		reassemblerMu.Unlock()
		if complete == nil {
			return
		}
		select {
		case responseCh <- complete:
		default:
		}
	}); err != nil {
		return nil, fmt.Errorf("enable notifications: %w", err)
	}

	payload, err := encodeBLERequest(req)
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}

	frame, err := encodeBLEFrame(bleMessageTypeRequest, payload)
	if err != nil {
		return nil, fmt.Errorf("frame request: %w", err)
	}

	fragmenter := newBLEFragmenter()
	fragments := fragmenter.fragment(frame)
	for _, fragment := range fragments {
		data := encodeBLEFragment(fragment)
		if _, err := requestChar.WriteWithoutResponse(data); err != nil {
			return nil, fmt.Errorf("write request fragment: %w", err)
		}
	}

	responseTimeout := timeout
	if responseTimeout <= 0 {
		responseTimeout = DefaultBLEScanTimeout
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(responseTimeout):
		return nil, fmt.Errorf("bluetooth response timeout")
	case responseData := <-responseCh:
		frame, err := decodeBLEFrame(responseData)
		if err != nil {
			return nil, fmt.Errorf("decode response frame: %w", err)
		}
		if frame.messageType != bleMessageTypeResponse {
			return nil, fmt.Errorf("unexpected response type: %d", frame.messageType)
		}
		return decodeBLEResponse(frame.payload)
	}
}

// ScanBLEDevices scans for AckAgent BLE devices and returns discovered entries.
func ScanBLEDevices(ctx context.Context, timeout time.Duration) ([]BLEDeviceInfo, error) {
	adapter := bluetooth.DefaultAdapter
	if err := adapter.Enable(); err != nil {
		return nil, err
	}

	serviceUUID, err := bluetooth.ParseUUID(BLEServiceUUID)
	if err != nil {
		return nil, err
	}

	if timeout <= 0 {
		timeout = DefaultBLEScanTimeout
	}

	scanCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	results := make(map[string]BLEDeviceInfo)
	var mu sync.Mutex
	stopOnce := sync.Once{}
	scanDone := make(chan error, 1)

	go func() {
		err := adapter.Scan(func(adapter *bluetooth.Adapter, result bluetooth.ScanResult) {
			if !result.HasServiceUUID(serviceUUID) {
				return
			}

			info := BLEDeviceInfo{
				Name:    strings.TrimSpace(result.LocalName()),
				Address: result.Address.String(),
				RSSI:    result.RSSI,
			}

			mu.Lock()
			if _, ok := results[info.Address]; !ok {
				results[info.Address] = info
			}
			mu.Unlock()
		})
		scanDone <- err
	}()

	select {
	case <-scanCtx.Done():
		stopOnce.Do(func() { adapter.StopScan() })
	case err := <-scanDone:
		if err != nil {
			return nil, err
		}
	}

	stopOnce.Do(func() { adapter.StopScan() })

	mu.Lock()
	defer mu.Unlock()
	list := make([]BLEDeviceInfo, 0, len(results))
	for _, info := range results {
		list = append(list, info)
	}
	return list, nil
}

// ensureEnabled initializes the adapter once.
func (t *BLETransport) ensureEnabled() error {
	t.enableOnce.Do(func() {
		t.enableErr = t.adapter.Enable()
	})
	return t.enableErr
}

type bleDeviceCandidate struct {
	address bluetooth.Address
	name    string
}

// findDevice scans for the first matching device.
func (t *BLETransport) findDevice(ctx context.Context) (*bleDeviceCandidate, error) {
	scanCtx, cancel := context.WithTimeout(ctx, t.scanTimeout)
	defer cancel()

	resultCh := make(chan *bleDeviceCandidate, 1)
	stopOnce := sync.Once{}
	scanDone := make(chan error, 1)

	go func() {
		err := t.adapter.Scan(func(adapter *bluetooth.Adapter, result bluetooth.ScanResult) {
			if !result.HasServiceUUID(t.serviceUUID) {
				return
			}
			if !deviceMatchesFilter(t.deviceFilter, result) {
				return
			}

			candidate := &bleDeviceCandidate{
				address: result.Address,
				name:    strings.TrimSpace(result.LocalName()),
			}

			select {
			case resultCh <- candidate:
				stopOnce.Do(func() { adapter.StopScan() })
			default:
			}
		})
		scanDone <- err
	}()

	select {
	case <-scanCtx.Done():
		stopOnce.Do(func() { t.adapter.StopScan() })
		return nil, ErrBLEDeviceNotFound
	case err := <-scanDone:
		if err != nil {
			return nil, err
		}
		return nil, ErrBLEDeviceNotFound
	case candidate := <-resultCh:
		stopOnce.Do(func() { t.adapter.StopScan() })
		return candidate, nil
	}
}

// connect establishes a BLE connection to the device.
func (t *BLETransport) connect(ctx context.Context, address bluetooth.Address) (bluetooth.Device, error) {
	type result struct {
		device bluetooth.Device
		err    error
	}

	ch := make(chan result, 1)
	go func() {
		device, err := t.adapter.Connect(address, bluetooth.ConnectionParams{})
		if err != nil {
			ch <- result{err: err}
			return
		}
		ch <- result{device: device}
	}()

	select {
	case <-ctx.Done():
		return bluetooth.Device{}, ctx.Err()
	case res := <-ch:
		if res.err != nil {
			return bluetooth.Device{}, res.err
		}
		return res.device, nil
	}
}

// discoverCharacteristics looks up the AckAgent request/response characteristics.
func (t *BLETransport) discoverCharacteristics(device bluetooth.Device) (*bluetooth.DeviceCharacteristic, *bluetooth.DeviceCharacteristic, error) {
	services, err := device.DiscoverServices([]bluetooth.UUID{t.serviceUUID})
	if err != nil {
		return nil, nil, err
	}
	if len(services) == 0 {
		return nil, nil, fmt.Errorf("ackagent service not found")
	}

	chars, err := services[0].DiscoverCharacteristics([]bluetooth.UUID{t.requestUUID, t.responseUUID})
	if err != nil {
		return nil, nil, err
	}

	var requestChar *bluetooth.DeviceCharacteristic
	var responseChar *bluetooth.DeviceCharacteristic
	for i := range chars {
		char := &chars[i]
		switch char.UUID() {
		case t.requestUUID:
			requestChar = char
		case t.responseUUID:
			responseChar = char
		}
	}

	if requestChar == nil || responseChar == nil {
		return nil, nil, fmt.Errorf("required characteristics not found")
	}

	return requestChar, responseChar, nil
}

// deviceMatchesFilter checks if the scan result matches the user filter.
func deviceMatchesFilter(filter string, result bluetooth.ScanResult) bool {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return true
	}

	address := strings.ToLower(result.Address.String())
	name := strings.ToLower(strings.TrimSpace(result.LocalName()))
	filterLower := strings.ToLower(filter)

	if filterLower == address {
		return true
	}
	if filterLower == name {
		return true
	}

	return strings.Contains(name, filterLower)
}

// parseBLEUUID parses a UUID string into a bluetooth.UUID.
