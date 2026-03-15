package transport

import "testing"

func TestBLEFragmentEncodeDecode(t *testing.T) {
	fragment := bleFragment{
		flags:    bleFragmentFirst | bleFragmentLast,
		sequence: 7,
		payload:  []byte{1, 2, 3, 4},
	}

	encoded := encodeBLEFragment(fragment)
	decoded, ok := decodeBLEFragment(encoded)
	if !ok {
		t.Fatalf("decodeBLEFragment failed")
	}

	if decoded.flags != fragment.flags {
		t.Fatalf("flags mismatch: got %d want %d", decoded.flags, fragment.flags)
	}
	if decoded.sequence != fragment.sequence {
		t.Fatalf("sequence mismatch: got %d want %d", decoded.sequence, fragment.sequence)
	}
	if string(decoded.payload) != string(fragment.payload) {
		t.Fatalf("payload mismatch: got %v want %v", decoded.payload, fragment.payload)
	}
}

func TestBLEFragmenterReassemblerSingle(t *testing.T) {
	payload := []byte{10, 20, 30}
	fragmenter := newBLEFragmenter()
	fragments := fragmenter.fragment(payload)
	if len(fragments) != 1 {
		t.Fatalf("expected 1 fragment, got %d", len(fragments))
	}

	reassembler := newBLEReassembler()
	result := reassembler.addFragment(fragments[0])
	if result == nil {
		t.Fatalf("expected result, got nil")
	}
	if string(result) != string(payload) {
		t.Fatalf("payload mismatch: got %v want %v", result, payload)
	}
}

func TestBLEFragmenterReassemblerMulti(t *testing.T) {
	payload := make([]byte, bleMaxPayloadSize*2+25)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	fragmenter := newBLEFragmenter()
	fragments := fragmenter.fragment(payload)
	if len(fragments) < 2 {
		t.Fatalf("expected multiple fragments, got %d", len(fragments))
	}

	reassembler := newBLEReassembler()
	var result []byte
	for _, fragment := range fragments {
		if complete := reassembler.addFragment(fragment); complete != nil {
			result = complete
		}
	}

	if result == nil {
		t.Fatalf("expected reassembled payload")
	}
	if string(result) != string(payload) {
		t.Fatalf("payload mismatch")
	}
}

func TestBLEReassemblerOutOfOrder(t *testing.T) {
	payload := make([]byte, bleMaxPayloadSize+10)
	for i := range payload {
		payload[i] = byte((i * 7) % 256)
	}

	fragmenter := newBLEFragmenter()
	fragments := fragmenter.fragment(payload)
	if len(fragments) < 2 {
		t.Fatalf("expected multiple fragments")
	}

	reassembler := newBLEReassembler()
	if result := reassembler.addFragment(fragments[1]); result != nil {
		t.Fatalf("expected nil for out-of-order fragment")
	}

	var result []byte
	for _, fragment := range fragments {
		if complete := reassembler.addFragment(fragment); complete != nil {
			result = complete
		}
	}

	if result == nil {
		t.Fatalf("expected reassembled payload")
	}
	if string(result) != string(payload) {
		t.Fatalf("payload mismatch")
	}
}

func TestBLEReassemblerMaxSize(t *testing.T) {
	// Create a payload larger than the max reassembly size
	payload := make([]byte, bleMaxReassemblyBytes+1)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	fragmenter := newBLEFragmenter()
	fragments := fragmenter.fragment(payload)

	reassembler := newBLEReassembler()
	var result []byte
	for _, fragment := range fragments {
		if complete := reassembler.addFragment(fragment); complete != nil {
			result = complete
		}
	}

	if result != nil {
		t.Fatalf("expected nil result for oversized message, got %d bytes", len(result))
	}

	// Verify reassembler can still process normal messages after rejection
	smallPayload := []byte{1, 2, 3}
	smallFragments := fragmenter.fragment(smallPayload)
	for _, fragment := range smallFragments {
		if complete := reassembler.addFragment(fragment); complete != nil {
			result = complete
		}
	}
	if result == nil {
		t.Fatalf("expected reassembler to recover after oversized rejection")
	}
	if string(result) != string(smallPayload) {
		t.Fatalf("payload mismatch after recovery")
	}
}
