package protocol

import (
	"errors"
	"testing"
)

func TestMarshalBinaryRoundTrip(t *testing.T) {
	want := Message{Type: MsgPing, StreamID: 42, Payload: []byte("synthetic")}
	wire, err := MarshalBinary(want)
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	got, err := Unmarshal(wire)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.Version != ProtocolVersion || got.Type != want.Type || got.StreamID != want.StreamID || string(got.Payload) != string(want.Payload) {
		t.Fatalf("round trip = %#v, want %#v", got, want)
	}
}

func TestMarshalBinaryRejectsOversizedPayload(t *testing.T) {
	_, err := MarshalBinary(Message{Payload: make([]byte, MaxPayloadSize+1)})
	if !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("error = %v, want ErrPayloadTooLarge", err)
	}
}

func TestUnmarshalRejectsTruncatedMessage(t *testing.T) {
	if _, err := Unmarshal([]byte{ProtocolVersion, byte(MsgPing)}); err == nil {
		t.Fatal("Unmarshal accepted a truncated message")
	}
}
