package channel

import (
	"fmt"
	"sync"
	"time"
)

type MultiChannel struct {
	channels   []Channel
	activeIdx  int
	mu         sync.Mutex
	rotateIntv time.Duration
	recvCh     chan []byte
	stopCh     chan struct{}
	onSwitch   func(from, to ChannelType)
}

func NewMultiChannel(rotateInterval time.Duration) *MultiChannel {
	if rotateInterval == 0 {
		rotateInterval = 30 * time.Second
	}
	return &MultiChannel{
		rotateIntv: rotateInterval,
		recvCh:     make(chan []byte, 256),
		stopCh:     make(chan struct{}),
	}
}

func (m *MultiChannel) AddChannel(ch Channel) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.channels = append(m.channels, ch)
	return nil
}

func (m *MultiChannel) ConnectAll(addr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var connected []Channel
	for _, ch := range m.channels {
		if err := ch.Connect(addr); err != nil {
			continue
		}
		connected = append(connected, ch)
		go m.receiveLoop(ch)
	}
	m.channels = connected
	if len(m.channels) == 0 {
		return fmt.Errorf("no channels could connect")
	}
	return nil
}

func (m *MultiChannel) StartRotation() {
	go func() {
		ticker := time.NewTicker(m.rotateIntv)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				m.rotate()
			case <-m.stopCh:
				return
			}
		}
	}()
}

func (m *MultiChannel) rotate() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.channels) <= 1 {
		return
	}

	oldIdx := m.activeIdx
	for i := 0; i < len(m.channels); i++ {
		candidate := (m.activeIdx + 1 + i) % len(m.channels)
		if candidate != oldIdx {
			old := m.channels[oldIdx].Info().Type
			new := m.channels[candidate].Info().Type
			m.activeIdx = candidate
			if m.onSwitch != nil {
				m.onSwitch(old, new)
			}
			return
		}
	}
}

func (m *MultiChannel) SetOnSwitch(fn func(from, to ChannelType)) {
	m.onSwitch = fn
}

func (m *MultiChannel) Send(data []byte) error {
	m.mu.Lock()
	if len(m.channels) == 0 {
		m.mu.Unlock()
		return fmt.Errorf("no channels")
	}
	ch := m.channels[m.activeIdx]
	m.mu.Unlock()

	err := ch.Send(data)
	if err != nil {
		m.mu.Lock()
		m.activeIdx = (m.activeIdx + 1) % len(m.channels)
		fallback := m.channels[m.activeIdx].Info().Type
		m.mu.Unlock()
		if m.onSwitch != nil {
			m.onSwitch(ch.Info().Type, fallback)
		}
		return m.channels[m.activeIdx].Send(data)
	}
	return nil
}

func (m *MultiChannel) Recv() ([]byte, error) {
	select {
	case data := <-m.recvCh:
		return data, nil
	case <-time.After(60 * time.Second):
		return nil, fmt.Errorf("recv timeout")
	}
}

func (m *MultiChannel) receiveLoop(ch Channel) {
	for {
		data, err := ch.Recv()
		if err != nil {
			return
		}
		select {
		case m.recvCh <- data:
		default:
		}
	}
}

func (m *MultiChannel) Close() error {
	close(m.stopCh)
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ch := range m.channels {
		ch.Close()
	}
	return nil
}

func (m *MultiChannel) Info() ChannelInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.channels) == 0 {
		return ChannelInfo{Type: "multi", Name: "Multi-Channel"}
	}
	return m.channels[m.activeIdx].Info()
}

func (m *MultiChannel) ActiveChannelType() ChannelType {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.channels) == 0 {
		return ""
	}
	return m.channels[m.activeIdx].Info().Type
}

func (m *MultiChannel) ChannelCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.channels)
}

func (m *MultiChannel) Connect(addr string) error {
	return m.ConnectAll(addr)
}
