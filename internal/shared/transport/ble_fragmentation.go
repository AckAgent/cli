package transport

const (
	bleMaxFragmentSize    = 500
	bleFragmentHeaderSize = 2
	bleMaxPayloadSize     = bleMaxFragmentSize - bleFragmentHeaderSize
)

const bleMaxReassemblyBytes = 65_536

const (
	bleFragmentFirst byte = 0x01
	bleFragmentLast  byte = 0x02
)

// bleFragment is a BLE fragment with flags, sequence, and payload.
type bleFragment struct {
	flags    byte
	sequence byte
	payload  []byte
}

// encodeBLEFragment encodes a fragment to wire format.
func encodeBLEFragment(fragment bleFragment) []byte {
	data := make([]byte, bleFragmentHeaderSize+len(fragment.payload))
	data[0] = fragment.flags
	data[1] = fragment.sequence
	copy(data[2:], fragment.payload)
	return data
}

// decodeBLEFragment decodes a fragment from wire format.
func decodeBLEFragment(data []byte) (bleFragment, bool) {
	if len(data) < bleFragmentHeaderSize {
		return bleFragment{}, false
	}

	return bleFragment{
		flags:    data[0],
		sequence: data[1],
		payload:  data[2:],
	}, true
}

// bleFragmenter splits messages into BLE-sized fragments.
type bleFragmenter struct {
	maxPayloadSize int
}

// newBLEFragmenter creates a BLE fragmenter with the default MTU.
func newBLEFragmenter() *bleFragmenter {
	return &bleFragmenter{maxPayloadSize: bleMaxPayloadSize}
}

// fragment splits a message into BLE fragments.
func (f *bleFragmenter) fragment(data []byte) []bleFragment {
	if len(data) == 0 {
		return []bleFragment{{
			flags:    bleFragmentFirst | bleFragmentLast,
			sequence: 0,
			payload:  []byte{},
		}}
	}

	fragments := make([]bleFragment, 0, (len(data)/f.maxPayloadSize)+1)
	offset := 0
	sequence := byte(0)

	for offset < len(data) {
		remaining := len(data) - offset
		chunkSize := remaining
		if chunkSize > f.maxPayloadSize {
			chunkSize = f.maxPayloadSize
		}

		flags := byte(0)
		if offset == 0 {
			flags |= bleFragmentFirst
		}
		if offset+chunkSize >= len(data) {
			flags |= bleFragmentLast
		}

		chunk := data[offset : offset+chunkSize]
		fragments = append(fragments, bleFragment{
			flags:    flags,
			sequence: sequence,
			payload:  chunk,
		})

		offset += chunkSize
		sequence++
	}

	return fragments
}

// bleReassembler reassembles BLE fragments into a complete message.
type bleReassembler struct {
	fragments        map[byte][]byte
	expectedNext     byte
	started          bool
	accumulatedBytes int
}

// newBLEReassembler creates a new BLE reassembler.
func newBLEReassembler() *bleReassembler {
	return &bleReassembler{fragments: make(map[byte][]byte)}
}

// addFragment adds a fragment and returns the full message if complete.
func (r *bleReassembler) addFragment(fragment bleFragment) []byte {
	if fragment.flags&bleFragmentFirst != 0 {
		r.reset()
		r.started = true
		r.expectedNext = 0
	}

	if !r.started {
		return nil
	}

	if fragment.sequence != r.expectedNext {
		r.reset()
		return nil
	}

	r.accumulatedBytes += len(fragment.payload)
	if r.accumulatedBytes > bleMaxReassemblyBytes {
		r.reset()
		return nil
	}

	r.fragments[fragment.sequence] = fragment.payload
	r.expectedNext++

	if fragment.flags&bleFragmentLast != 0 {
		result := make([]byte, 0)
		for seq := byte(0); seq < r.expectedNext; seq++ {
			if payload, ok := r.fragments[seq]; ok {
				result = append(result, payload...)
			}
		}
		r.reset()
		return result
	}

	return nil
}

// reset clears the reassembler state.
func (r *bleReassembler) reset() {
	r.fragments = make(map[byte][]byte)
	r.expectedNext = 0
	r.started = false
	r.accumulatedBytes = 0
}
