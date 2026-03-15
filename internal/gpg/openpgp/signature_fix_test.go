package openpgp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildEdDSASigBody builds a V4 EdDSA signature body (without packet header)
// with the given MPI data at the end.
func buildEdDSASigBody(mpiData []byte) []byte {
	// Build minimal hashed subpackets (creation time)
	hashedSub := NewSubpacketBuilder()
	hashedSub.AddCreationTime(time.Unix(1700000000, 0))
	hashed := hashedSub.Bytes()

	// No unhashed subpackets
	pw := NewPacketWriter()

	// V4 signature header
	pw.WriteByte(SigVersion4)                  // version
	pw.WriteByte(SigTypePositiveCertification) // sig type (0x13)
	pw.WriteByte(PubKeyAlgoEdDSA)              // pub algo (22)
	pw.WriteByte(HashAlgoSHA256)               // hash algo
	pw.WriteUint16(uint16(len(hashed)))        // hashed subpacket length
	pw.Write(hashed)                           // hashed subpackets
	pw.WriteUint16(0)                          // unhashed subpacket length (none)
	pw.WriteByte(0xAB)                         // hash left 2 (arbitrary)
	pw.WriteByte(0xCD)
	pw.Write(mpiData) // MPI data

	return pw.Bytes()
}

// buildEdDSASigPacket builds a complete EdDSA signature packet with the given MPI data.
func buildEdDSASigPacket(mpiData []byte) []byte {
	body := buildEdDSASigBody(mpiData)
	return BuildPacket(PacketTagSignature, body)
}

// buildECDSASigPacket builds a complete ECDSA (non-EdDSA) signature packet.
func buildECDSASigPacket() []byte {
	hashedSub := NewSubpacketBuilder()
	hashedSub.AddCreationTime(time.Unix(1700000000, 0))
	hashed := hashedSub.Bytes()

	pw := NewPacketWriter()
	pw.WriteByte(SigVersion4)
	pw.WriteByte(SigTypePositiveCertification)
	pw.WriteByte(PubKeyAlgoECDSA) // ECDSA, not EdDSA
	pw.WriteByte(HashAlgoSHA256)
	pw.WriteUint16(uint16(len(hashed)))
	pw.Write(hashed)
	pw.WriteUint16(0)
	pw.WriteByte(0xAB)
	pw.WriteByte(0xCD)

	// Two valid ECDSA MPIs (32 bytes each)
	r := make([]byte, 32)
	s := make([]byte, 32)
	r[0] = 0x01
	s[0] = 0x02
	pw.Write(EncodeMPIFromBytes(r))
	pw.Write(EncodeMPIFromBytes(s))

	return BuildPacket(PacketTagSignature, pw.Bytes())
}

func TestFixEdDSASignatureMPIs_SplitsCombinedMPI(t *testing.T) {
	// Build a 64-byte combined R||S value
	combined := make([]byte, 64)
	for i := range combined {
		combined[i] = byte(i + 1) // non-zero for deterministic checking
	}
	singleMPI := EncodeMPIFromBytes(combined)
	packet := buildEdDSASigPacket(singleMPI)

	fixed := FixEdDSASignatureMPIs(packet)

	// Parse the fixed packet
	reader := NewPacketReader(fixed)
	parsed, err := reader.Next()
	require.NoError(t, err)
	assert.Equal(t, byte(PacketTagSignature), parsed.Tag)

	// Navigate to MPIs in the fixed body
	body := parsed.Body
	offset := 4 // version + sigType + pubAlgo + hashAlgo
	hashedLen := int(body[offset])<<8 | int(body[offset+1])
	offset += 2 + hashedLen
	unhashedLen := int(body[offset])<<8 | int(body[offset+1])
	offset += 2 + unhashedLen
	offset += 2 // hash left 2

	// Decode first MPI (R)
	rVal, rConsumed, err := DecodeMPI(body, offset)
	require.NoError(t, err)
	assert.Len(t, rVal, 32, "R should be 32 bytes")
	assert.Equal(t, combined[:32], rVal, "R should be first 32 bytes of original")

	// Decode second MPI (S)
	sVal, _, err := DecodeMPI(body, offset+rConsumed)
	require.NoError(t, err)
	assert.Len(t, sVal, 32, "S should be 32 bytes")
	assert.Equal(t, combined[32:], sVal, "S should be last 32 bytes of original")
}

func TestFixEdDSASignatureMPIs_AlreadyCorrectTwoMPIs(t *testing.T) {
	// Build a packet with two correct 32-byte MPIs
	r := make([]byte, 32)
	s := make([]byte, 32)
	r[0] = 0x01
	s[0] = 0x02

	twoMPIs := append(EncodeMPIFromBytes(r), EncodeMPIFromBytes(s)...)
	packet := buildEdDSASigPacket(twoMPIs)

	fixed := FixEdDSASignatureMPIs(packet)
	assert.Equal(t, packet, fixed, "already-correct packet should be unchanged")
}

func TestFixEdDSASignatureMPIs_NonEdDSAUnchanged(t *testing.T) {
	packet := buildECDSASigPacket()
	fixed := FixEdDSASignatureMPIs(packet)
	assert.Equal(t, packet, fixed, "non-EdDSA packet should be unchanged")
}

func TestFixEdDSASignatureMPIs_RoundTrip(t *testing.T) {
	// Build packet with bad MPI, fix it, verify structure is parseable
	combined := make([]byte, 64)
	combined[0] = 0xFF
	combined[32] = 0xEE
	singleMPI := EncodeMPIFromBytes(combined)
	packet := buildEdDSASigPacket(singleMPI)

	fixed := FixEdDSASignatureMPIs(packet)

	// Verify it's a valid packet by parsing
	reader := NewPacketReader(fixed)
	parsed, err := reader.Next()
	require.NoError(t, err)
	assert.Equal(t, byte(PacketTagSignature), parsed.Tag)
	assert.True(t, len(parsed.Body) > 10, "body should contain valid signature data")
}

func TestFixEdDSASignatureMPIs_EmptyAndNilInput(t *testing.T) {
	assert.Nil(t, FixEdDSASignatureMPIs(nil))
	assert.Equal(t, []byte{}, FixEdDSASignatureMPIs([]byte{}))
}

func TestFixEdDSASignatureMPIs_Idempotent(t *testing.T) {
	// Applying the fix twice should produce the same result
	combined := make([]byte, 64)
	for i := range combined {
		combined[i] = byte(i)
	}
	singleMPI := EncodeMPIFromBytes(combined)
	packet := buildEdDSASigPacket(singleMPI)

	fixed1 := FixEdDSASignatureMPIs(packet)
	fixed2 := FixEdDSASignatureMPIs(fixed1)
	assert.Equal(t, fixed1, fixed2, "applying fix twice should be idempotent")
}
