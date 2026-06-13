package channel

import (
	"fmt"

	"github.com/byjanke/ghostlink/pkg/crypto"
)

const (
	msgHandshakeInit = 0x01
	msgHandshakeResp = 0x02
	msgEncryptedData = 0x03
)

func ClientHandshake(ch Channel) ([]byte, error) {
	priv, pub, err := crypto.GenerateKeyExchange()
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	init := append([]byte{msgHandshakeInit}, pub...)
	if err := ch.Send(init); err != nil {
		return nil, fmt.Errorf("send init: %w", err)
	}

	resp, err := ch.Recv()
	if err != nil {
		return nil, fmt.Errorf("recv resp: %w", err)
	}

	if len(resp) < 2 || resp[0] != msgHandshakeResp {
		return nil, fmt.Errorf("invalid handshake response: len=%d type=%x", len(resp), resp[0])
	}

	shared, err := crypto.CompleteKeyExchange(priv, resp[1:])
	if err != nil {
		return nil, fmt.Errorf("complete ke: %w", err)
	}

	key := crypto.DeriveKey(shared, "ghostlink-ecdhe-v1")
	return key, nil
}

func ServerHandshake(ch Channel) ([]byte, error) {
	init, err := ch.Recv()
	if err != nil {
		return nil, fmt.Errorf("recv init: %w", err)
	}

	if len(init) < 2 || init[0] != msgHandshakeInit {
		return nil, fmt.Errorf("invalid handshake init: len=%d type=%x", len(init), init[0])
	}

	priv, pub, err := crypto.GenerateKeyExchange()
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	resp := append([]byte{msgHandshakeResp}, pub...)
	if err := ch.Send(resp); err != nil {
		return nil, fmt.Errorf("send resp: %w", err)
	}

	shared, err := crypto.CompleteKeyExchange(priv, init[1:])
	if err != nil {
		return nil, fmt.Errorf("complete ke: %w", err)
	}

	key := crypto.DeriveKey(shared, "ghostlink-ecdhe-v1")
	return key, nil
}
