// TCP packet framing for ProudNet.
//
// ProudNet wraps each logical RMI message in a frame. The exact framing format
// observed in network captures follows this pattern (based on ProudNet sample
// code analysis, to be verified against a live capture):
//
//   [ MessageType: 1 byte ] [ HostID dest: int32 (compact) ] [ RMI ID: int32 (compact) ]
//   [ Encrypted body... ]
//
// The TCP stream has its own outer framing too -- typically a length-prefixed
// chunk per IO event. ProudNet uses a "Final User Work Item" boundary marker.
//
// THIS FILE IS A SCAFFOLD. The exact byte layout will be refined once we capture
// a real handshake from the Goley client.
package proudnet

import (
	"encoding/binary"
	"errors"
	"io"
)

// MessageType -- internal message-class tag (first byte of each frame).
// Values are guesses based on ProudNet header comments; live capture required.
type MessageType byte

const (
	MessageTypeRMI       MessageType = 0x01 // typical RMI call
	MessageTypeUserMsg   MessageType = 0x02 // SendUserMessage path
	MessageTypeRequestServerTime MessageType = 0x10
	MessageTypeServerHolepunch   MessageType = 0x20
	MessageTypePeerToPeer        MessageType = 0x30
	MessageTypeConnectServerTimedout MessageType = 0xFE
	MessageTypeNotifyServerConnectionHint MessageType = 0xFF
)

// Frame represents a parsed inbound message.
type Frame struct {
	MsgType MessageType
	DestID  HostID
	RmiID   int32 // 0 if not an RMI message
	Body    []byte
}

// ReadFrame reads a single framed message from the connection. Assumes the
// outer length prefix is a uint16 little-endian (placeholder -- verify).
//
// NOTE: This is a *guess* at the wire format. We will revise after capturing
// a real Goley handshake.
func ReadFrame(r io.Reader) (*Frame, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	frameLen := binary.LittleEndian.Uint16(lenBuf[:])
	if frameLen == 0 {
		return nil, errors.New("proudnet: zero-length frame")
	}
	body := make([]byte, frameLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	if len(body) < 1 {
		return nil, errors.New("proudnet: frame too short for header")
	}

	f := &Frame{
		MsgType: MessageType(body[0]),
		Body:    body[1:],
	}
	return f, nil
}

// WriteFrame sends a framed message.
func WriteFrame(w io.Writer, mt MessageType, body []byte) error {
	payload := make([]byte, 1+len(body))
	payload[0] = byte(mt)
	copy(payload[1:], body)

	var lenBuf [2]byte
	binary.LittleEndian.PutUint16(lenBuf[:], uint16(len(payload)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// WriteRMI builds and sends an RMI call from server to client.
func WriteRMI(w io.Writer, dest HostID, rmiID int32, args *Message) error {
	body := NewMessage()
	body.WriteHostID(dest)
	body.WriteInt32(rmiID)
	body.WriteBytes(args.Bytes())
	return WriteFrame(w, MessageTypeRMI, body.Bytes())
}
