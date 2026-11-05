package session

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"github.com/byjanke/ghostlink/pkg/adaptive"
	"github.com/byjanke/ghostlink/pkg/channel"
	"github.com/byjanke/ghostlink/pkg/crypto"
	"github.com/byjanke/ghostlink/pkg/encoder"
)

type SessionState int

const (
	StateInit SessionState = iota
	StateKeyExchange
	StateActive
	StateClosed
)

type Session struct {
	mu        sync.Mutex
	state     SessionState
	channels  map[channel.ChannelType]channel.Channel
	active    channel.ChannelType
	analyzer  *adaptive.EntropyAnalyzer
	crypto    *crypto.Session
	isServer  bool
	listener  channel.Listener
	peerAddr  string
	onReceive func([]byte)
}

func NewServer() *Session {
	return &Session{
		channels: make(map[channel.ChannelType]channel.Channel),
		analyzer: adaptive.NewEntropyAnalyzer(),
		state:    StateInit,
		isServer: true,
	}
}

func NewClient(serverAddr string) *Session {
	return &Session{
		channels: make(map[channel.ChannelType]channel.Channel),
		analyzer: adaptive.NewEntropyAnalyzer(),
		state:    StateInit,
		isServer: false,
		peerAddr: serverAddr,
	}
}

func (s *Session) AddChannel(ct channel.ChannelType) error {
	ch := channel.NewChannel(ct)
	if ch == nil {
		return fmt.Errorf("unknown channel type: %s", ct)
	}
	s.channels[ct] = ch
	s.analyzer.RegisterChannel(ch)
	return nil
}

func (s *Session) OnReceive(callback func([]byte)) {
	s.onReceive = callback
}

func (s *Session) Connect() error {
	if s.isServer {
		return fmt.Errorf("server sessions use Listen(), not Connect()")
	}

	for ct, ch := range s.channels {
		info := ch.Info()
		log.Printf("connecting channel %s (%s) -> %s", ct, info.Name, s.peerAddr)
		if err := ch.Connect(s.peerAddr); err != nil {
			log.Printf("channel %s failed: %v (fallback available)", ct, err)
			delete(s.channels, ct)
		}
	}

	if len(s.channels) == 0 {
		return fmt.Errorf("no channels could connect")
	}

	s.state = StateKeyExchange
	if err := s.performKeyExchange(); err != nil {
		return fmt.Errorf("key exchange: %w", err)
	}

	s.state = StateActive
	return nil
}

func (s *Session) Listen(addr string) error {
	for ct := range s.channels {
		listener := channel.NewListener(ct)
		if listener == nil {
			continue
		}
		if err := listener.Listen(addr); err != nil {
			log.Printf("listener %s failed: %v", ct, err)
			continue
		}
		s.listener = listener
		go s.acceptLoop(listener)
	}

	if s.listener == nil {
		return fmt.Errorf("no listeners could start")
	}

	return nil
}

func (s *Session) acceptLoop(l channel.Listener) {
	for {
		ch, addr, err := l.Accept()
		if err != nil {
			if s.state == StateClosed {
				return
			}
			log.Printf("accept error: %v", err)
			continue
		}
		info := ch.Info()
		log.Printf("accepted %s from %v", info.Type, addr)
		s.mu.Lock()
		s.channels[info.Type] = ch
		s.active = info.Type
		s.mu.Unlock()

		if s.state == StateInit {
			s.state = StateKeyExchange
			if err := s.performKeyExchange(); err != nil {
				log.Printf("key exchange failed: %v", err)
			}
			s.state = StateActive
		}

		go s.receiveLoop(ch)
	}
}

func (s *Session) receiveLoop(ch channel.Channel) {
	for s.state == StateActive {
		data, err := ch.Recv()
		if err != nil {
			if err == io.EOF {
				return
			}
			log.Printf("recv error on %s: %v", ch.Info().Type, err)
			s.analyzer.UpdateScore(ch.Info().Type, false, 0)
			continue
		}

		start := time.Now()
		decrypted, err := s.crypto.Decrypt(data)
		if err != nil {
			log.Printf("decrypt error: %v", err)
			continue
		}

		frame, err := encoder.UnmarshalFrame(decrypted)
		if err != nil {
			log.Printf("unmarshal frame: %v", err)
			continue
		}

		if s.onReceive != nil {
			s.onReceive(frame.Payload)
		}

		s.analyzer.UpdateScore(ch.Info().Type, true, time.Since(start))
	}
}

func (s *Session) Send(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state != StateActive {
		return fmt.Errorf("session not active")
	}

	encoded, err := encoder.Encode(data)
	if err != nil {
		return fmt.Errorf("encode: %w", err)
	}

	frames, err := encoder.SplitIntoFrames(encoded, 512)
	if err != nil {
		return fmt.Errorf("split frames: %w", err)
	}

	ct := s.analyzer.Select()

	ch, ok := s.channels[ct]
	if !ok {
		var fallback channel.ChannelType
		for ft := range s.channels {
			fallback = ft
			break
		}
		ct = fallback
		ch = s.channels[ct]
	}

	for _, frame := range frames {
		raw := encoder.MarshalFrame(frame)

		encrypted, err := s.crypto.Encrypt(raw)
		if err != nil {
			log.Printf("encrypt error: %v", err)
			continue
		}

		if err := ch.Send(encrypted); err != nil {
			log.Printf("send error on %s: %v (will retry on next channel)", ct, err)
			s.analyzer.UpdateScore(ct, false, 0)
			s.active = s.analyzer.Select()
			continue
		}

		s.analyzer.UpdateScore(ct, true, 100*time.Millisecond)
	}

	return nil
}

func (s *Session) performKeyExchange() error {
	priv, pubBytes, err := crypto.GenerateKeyExchange()
	if err != nil {
		return err
	}

	msg := map[string]interface{}{
		"type":    "key_exchange",
		"pub_key": pubBytes,
	}
	payload, _ := json.Marshal(msg)
	frames, _ := encoder.SplitIntoFrames(payload, 256)

	for ct, ch := range s.channels {
		for _, frame := range frames {
			raw := encoder.MarshalFrame(frame)
			if err := ch.Send(raw); err != nil {
				log.Printf("key exchange via %s failed: %v", ct, err)
				continue
			}
		}

		resp, err := ch.Recv()
		if err != nil {
			continue
		}

		var respMsg map[string]interface{}
		if err := json.Unmarshal(resp, &respMsg); err != nil {
			continue
		}

		if respMsg["type"] == "key_exchange" {
			peerPub, ok := respMsg["pub_key"].([]byte)
			if !ok {
				if b64, ok := respMsg["pub_key"].(string); ok {
					peerPub = []byte(b64)
				} else {
					continue
				}
			}

			shared, err := crypto.CompleteKeyExchange(priv, peerPub)
			if err != nil {
				return fmt.Errorf("complete key exchange: %w", err)
			}

			key := crypto.DeriveKey(shared, "ghostlink-session-v1")
			s.crypto, err = crypto.NewSession(key)
			if err != nil {
				return fmt.Errorf("create session: %w", err)
			}

			log.Printf("key exchange complete via %s", ct)
			return nil
		}
	}

	return fmt.Errorf("key exchange failed on all channels")
}

func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.state = StateClosed

	for _, ch := range s.channels {
		ch.Close()
	}

	if s.listener != nil {
		s.listener.Close()
	}

	return nil
}

func (s *Session) State() SessionState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

func (s *Session) Reconnect(addr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state == StateClosed {
		return fmt.Errorf("session permanently closed")
	}

	for ct, ch := range s.channels {
		ch.Close()
		newCh := channel.NewChannel(ct)
		if newCh == nil {
			continue
		}
		if err := newCh.Connect(addr); err != nil {
			log.Printf("reconnect %s failed: %v", ct, err)
			continue
		}
		s.channels[ct] = newCh
		s.analyzer.RegisterChannel(newCh)
		log.Printf("reconnected channel %s", ct)
	}

	if len(s.channels) == 0 {
		return fmt.Errorf("all channels failed to reconnect")
	}

	s.state = StateActive
	return nil
}

func encodePubKey(pub []byte) string {
	return fmt.Sprintf("%x", pub)
}

func itob(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}
