// CMessage equivalent -- bit-stream serialization for ProudNet messages.
//
// ProudNet uses a custom bit-packed serialization format. Scalars are
// variable-length encoded (CompactScalarValue): small numbers take 1 byte,
// larger ones take more. This package implements the wire format observed
// in the official ProudNet sample code and SDK headers.
package proudnet

import (
	"encoding/binary"
	"errors"
	"math"
)

// Message is a bit-aligned read/write buffer mirroring Proud::CMessage.
// Most game RMI traffic is byte-aligned, but the format allows individual
// bit fields for compactness.
type Message struct {
	buf []byte
	// Read cursor in BITS (not bytes).
	rBit int
	// Write cursor in BITS. Tracks the last written bit so partial trailing
	// bytes can be appended atomically.
	wBit int
}

// NewMessage creates an empty message for writing.
func NewMessage() *Message {
	return &Message{buf: make([]byte, 0, 64)}
}

// FromBytes wraps an existing payload for reading.
func FromBytes(data []byte) *Message {
	return &Message{buf: data, wBit: len(data) * 8}
}

// Bytes returns the underlying payload (used when sending).
func (m *Message) Bytes() []byte {
	return m.buf
}

// Len returns the byte length of the message.
func (m *Message) Len() int {
	return len(m.buf)
}

// =============================================================================
// Byte-aligned writes (the common case for game RMI)
// =============================================================================

func (m *Message) alignWrite() {
	// Round wBit up to next byte boundary; pad with zero bits.
	pad := (8 - (m.wBit & 7)) & 7
	m.wBit += pad
}

func (m *Message) ensure(extra int) {
	needed := (m.wBit + extra*8 + 7) / 8
	for len(m.buf) < needed {
		m.buf = append(m.buf, 0)
	}
}

// WriteBytes appends raw bytes (byte-aligned).
func (m *Message) WriteBytes(b []byte) {
	m.alignWrite()
	m.ensure(len(b))
	off := m.wBit / 8
	copy(m.buf[off:], b)
	m.wBit += len(b) * 8
}

// WriteInt32 writes a little-endian int32.
func (m *Message) WriteInt32(v int32) {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(v))
	m.WriteBytes(b[:])
}

// WriteUint32 writes a little-endian uint32.
func (m *Message) WriteUint32(v uint32) {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	m.WriteBytes(b[:])
}

// WriteInt64 writes a little-endian int64.
func (m *Message) WriteInt64(v int64) {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], uint64(v))
	m.WriteBytes(b[:])
}

// WriteFloat32 writes a little-endian float32.
func (m *Message) WriteFloat32(v float32) {
	m.WriteUint32(math.Float32bits(v))
}

// WriteByte writes a single byte.
func (m *Message) WriteByte(v byte) error {
	m.WriteBytes([]byte{v})
	return nil
}

// WriteBool writes a boolean as a single byte (0 or 1). Some sample code uses
// a single bit instead; we use the byte form for byte-alignment compatibility.
func (m *Message) WriteBool(v bool) {
	if v {
		m.WriteByte(1)
	} else {
		m.WriteByte(0)
	}
}

// WriteHostID writes a 32-bit HostID.
func (m *Message) WriteHostID(id HostID) {
	m.WriteInt32(int32(id))
}

// WriteString writes a Proud::String -- length-prefixed UTF-16LE (Windows wide).
// Format: uint32 char_count, then char_count * 2 bytes UTF-16LE.
// This matches CMessage::Write(const wchar_t* / const Proud::String &).
func (m *Message) WriteString(s string) {
	utf16 := stringToUTF16LE(s)
	m.WriteUint32(uint32(len(utf16) / 2))
	m.WriteBytes(utf16)
}

// WriteCompactInt32 writes a variable-length integer (ProudNet
// CompactScalarValue). Small values fit in 1-2 bytes; large values take
// up to 5 bytes. Currently using a simple fallback form (full int32)
// until the exact encoding is verified.
func (m *Message) WriteCompactInt32(v int32) {
	// TODO: verify compact encoding against a real capture.
	// For now, emit the raw int32 form.
	m.WriteInt32(v)
}

// =============================================================================
// Reads
// =============================================================================

func (m *Message) alignRead() {
	pad := (8 - (m.rBit & 7)) & 7
	m.rBit += pad
}

// ReadBytes consumes n bytes (byte-aligned).
func (m *Message) ReadBytes(n int) ([]byte, error) {
	m.alignRead()
	off := m.rBit / 8
	if off+n > len(m.buf) {
		return nil, errors.New("proudnet: short read")
	}
	out := make([]byte, n)
	copy(out, m.buf[off:off+n])
	m.rBit += n * 8
	return out, nil
}

func (m *Message) ReadInt32() (int32, error) {
	b, err := m.ReadBytes(4)
	if err != nil {
		return 0, err
	}
	return int32(binary.LittleEndian.Uint32(b)), nil
}

func (m *Message) ReadUint32() (uint32, error) {
	b, err := m.ReadBytes(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}

func (m *Message) ReadInt64() (int64, error) {
	b, err := m.ReadBytes(8)
	if err != nil {
		return 0, err
	}
	return int64(binary.LittleEndian.Uint64(b)), nil
}

func (m *Message) ReadFloat32() (float32, error) {
	v, err := m.ReadUint32()
	if err != nil {
		return 0, err
	}
	return math.Float32frombits(v), nil
}

func (m *Message) ReadBool() (bool, error) {
	b, err := m.ReadBytes(1)
	if err != nil {
		return false, err
	}
	return b[0] != 0, nil
}

func (m *Message) ReadHostID() (HostID, error) {
	v, err := m.ReadInt32()
	return HostID(v), err
}

// ReadString reads a UTF-16LE Proud::String.
func (m *Message) ReadString() (string, error) {
	n, err := m.ReadUint32()
	if err != nil {
		return "", err
	}
	if n > 1<<20 {
		return "", errors.New("proudnet: string too long")
	}
	raw, err := m.ReadBytes(int(n) * 2)
	if err != nil {
		return "", err
	}
	return utf16LEToString(raw), nil
}

// =============================================================================
// Utility -- UTF-16LE encoding helpers (works for BMP characters only;
// surrogate pairs not yet implemented).
// =============================================================================

func stringToUTF16LE(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		out = append(out, byte(r&0xff), byte(r>>8))
	}
	return out
}

func utf16LEToString(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	runes := make([]rune, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		runes = append(runes, rune(b[i])|rune(b[i+1])<<8)
	}
	return string(runes)
}
